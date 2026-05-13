import express from "express";
import axios from "axios";
import "dotenv/config";
import {createClient} from "@supabase/supabase-js";
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from "crypto";
import cron from 'node-cron';
import cookieParser from 'cookie-parser';

// Get __dirname equivalent for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Trust proxy (important for Render and other hosting services)
app.set('trust proxy', 1);

// Serve static files from public folder (Vercel serves this automatically)
// This is for local development - Vercel serves /public automatically
app.use(express.static(path.join(__dirname, 'public')));

// Cookie parser for reading cookies
app.use(cookieParser());

// Validate required environment variables
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_ANON_KEY) {
	console.error('Missing required Supabase environment variables');
}

const supabase = createClient(
	process.env.SUPABASE_URL || '', 
	process.env.SUPABASE_ANON_KEY || ''
);

// JWT utils
const JWT_SECRET = process.env.JWT_SECRET || process.env.SESSION_SECRET || 'fallback-secret-change-in-production';
const ACCESS_TOKEN_EXPIRY = '15m';       // 15 minutes
const REFRESH_TOKEN_EXPIRY = '7d';       // 7 days

function signToken(payload, expiresIn) {
	const header = { alg: 'HS256', typ: 'JWT' };
	const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
	const body = { ...payload, exp: Math.floor(Date.now() / 1000) + parseDuration(expiresIn) };
	const encodedBody = Buffer.from(JSON.stringify(body)).toString('base64url');
	const signature = crypto
		.createHmac('sha256', JWT_SECRET)
		.update(`${encodedHeader}.${encodedBody}`)
		.digest('base64url');
	return `${encodedHeader}.${encodedBody}.${signature}`;
}

function verifyToken(token) {
	const [encodedHeader, encodedBody, signature] = token.split('.');
	if (!encodedHeader || !encodedBody || !signature) throw new Error('Invalid token');
	const expectedSignature = crypto
		.createHmac('sha256', JWT_SECRET)
		.update(`${encodedHeader}.${encodedBody}`)
		.digest('base64url');
	if (signature !== expectedSignature) throw new Error('Invalid signature');
	const body = JSON.parse(Buffer.from(encodedBody, 'base64url').toString());
	if (body.exp && Date.now() >= body.exp * 1000) throw new Error('Token expired');
	return body;
}

function parseDuration(str) {
	const units = { s: 1, m: 60, h: 3600, d: 86400 };
	const match = str.match(/^(\d+)([smhd])$/);
	return match ? parseInt(match[1]) * units[match[2]] : 3600;
}

// Cookie config
const COOKIE_NAME = 'callmeout.access_token';
const REFRESH_COOKIE_NAME = 'callmeout.refresh_token';
const isProduction = process.env.NODE_ENV === 'production';
const cookieOptions = {
	httpOnly: true,
	secure: process.env.FORCE_SECURE_COOKIES === 'true' || isProduction,
	sameSite: 'lax',
	maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
};

// Auth middleware
function authenticateToken(request, response, next) {
	const accessToken = request.cookies?.[COOKIE_NAME];
	const refreshToken = request.cookies?.[REFRESH_COOKIE_NAME];

	if (accessToken) {
		try {
			const payload = verifyToken(accessToken);
			request.userId = payload.userId;
			return next();
		} catch (err) {
			// Access token expired or invalid, try refresh
			if (refreshToken) {
				try {
					const refreshPayload = verifyToken(refreshToken);
					const newAccessToken = signToken({ userId: refreshPayload.userId }, ACCESS_TOKEN_EXPIRY);
					response.cookie(COOKIE_NAME, newAccessToken, { ...cookieOptions, maxAge: 15 * 60 * 1000 });
					request.userId = refreshPayload.userId;
					return next();
				} catch (refreshErr) {
					// Refresh token also invalid
					response.clearCookie(COOKIE_NAME, cookieOptions);
					response.clearCookie(REFRESH_COOKIE_NAME, cookieOptions);
					return response.status(401).json({ error: 'Unauthorized' });
				}
			}
			response.clearCookie(COOKIE_NAME, cookieOptions);
			return response.status(401).json({ error: 'Unauthorized' });
		}
	}

	if (refreshToken) {
		try {
			const refreshPayload = verifyToken(refreshToken);
			const newAccessToken = signToken({ userId: refreshPayload.userId }, ACCESS_TOKEN_EXPIRY);
			response.cookie(COOKIE_NAME, newAccessToken, { ...cookieOptions, maxAge: 15 * 60 * 1000 });
			request.userId = refreshPayload.userId;
			return next();
		} catch (refreshErr) {
			response.clearCookie(COOKIE_NAME, cookieOptions);
			response.clearCookie(REFRESH_COOKIE_NAME, cookieOptions);
			return response.status(401).json({ error: 'Unauthorized' });
		}
	}

	return response.status(401).json({ error: 'Unauthorized' });
}

function optionalAuth(request, response, next) {
	const accessToken = request.cookies?.[COOKIE_NAME];
	if (accessToken) {
		try {
			const payload = verifyToken(accessToken);
			request.userId = payload.userId;
		} catch (err) {
			// Optionally try refresh token
			const refreshToken = request.cookies?.[REFRESH_COOKIE_NAME];
			if (refreshToken) {
				try {
					const refreshPayload = verifyToken(refreshToken);
					const newAccessToken = signToken({ userId: refreshPayload.userId }, ACCESS_TOKEN_EXPIRY);
					response.cookie(COOKIE_NAME, newAccessToken, { ...cookieOptions, maxAge: 15 * 60 * 1000 });
					request.userId = refreshPayload.userId;
				} catch (refreshErr) {
					// Silent fail for optional auth
				}
			}
		}
	}
	next();
}

// Webhook route must be defined BEFORE express.json() to get raw body
app.post('/api/gitwebhook', express.raw({type: 'application/json'}), async (request, response) => {
	const githubSignature = request.get('X-Hub-Signature-256');
	const gitWebhookSecret = process.env.GITWEBHOOK_SECRET;
	const hmac = crypto.createHmac('sha256', gitWebhookSecret);
	hmac.update(request.body);
	const ourSignature = 'sha256=' + hmac.digest('hex');
	if (!crypto.timingSafeEqual(Buffer.from(ourSignature), Buffer.from(githubSignature))) {
		console.warn('Recieved webhook with invalid signature');
		return response.status(401).send("Invalid Signature");		
	};
	console.log('Webhook Signature verified successfully');
	const pushEvent = JSON.parse(request.body.toString());
	console.log('--- RECEIVED GITHUB PAYLOAD ---');
    console.log(JSON.stringify(pushEvent, null, 2));
    console.log('--- END OF PAYLOAD ---');
	const {data:pushData, error:userError} = await supabase
		.from('users')
		.select('id')
		.eq('github_id', pushEvent.sender.id)
		.single();
	if (!pushData || userError) {
		console.error('Unable to locate user webhook:', userError);
		return response.status(404).send('User not Found');
	}
	const {error:counterUpsertError} = await supabase.rpc('increment_push_counter', {
		user_id_in: pushData.id
	});
	if (counterUpsertError) {
			console.error('Unable to upsert data:', counterUpsertError);
			return response.status(500).send("Data not updated")
	}
	else {
		return response.status(200).send('Webhook recieved successfully')
	};
});

// JSON parsing middleware for other routes
app.use(express.json());

app.get('/', (request, response) => {
	// If user is already logged in, redirect to dashboard
	if (request.userId) {
		response.redirect('/dashboard');
	} else {
		response.sendFile(path.join(__dirname, 'index.html'));
	}
});

app.get('/callback', async (request, response) => {
	try {
		const code = request.query.code;
		const tokenUrl = 'https://github.com/login/oauth/access_token'
		const gitData = {
			client_id: process.env.GITHUB_CLIENT_ID,
			client_secret: process.env.GITHUB_CLIENT_SECRET,
			code: code,
		};
		const githubResponse = await axios.post(tokenUrl, gitData, {
			headers: {
				'Accept': 'application/json'
			}
		});
		const accessToken = githubResponse.data.access_token;
		const authDetailsUrl = 'https://api.github.com/user'
		const authenticatedResponse = await axios.get(authDetailsUrl, {
			headers: {
				'Accept': 'application/json',
				'Authorization': `Bearer ${accessToken}`
			}
		});
		const userDataGit = authenticatedResponse.data;
		const saveDataGit = {
			github_id: userDataGit.id,
			github_username: userDataGit.login,
			github_access_token: accessToken,
		};
		const {data: userData, error} = await supabase
			.from ('users')
			.upsert(saveDataGit, {onConflict: 'github_id'})
			.select()
			.single();
		if (error) {
			console.error('Error saving user to database:', error);
			throw error;
		}

		// Issue JWT tokens
		const userId = userData.id;
		const jwtAccess = signToken({ userId }, ACCESS_TOKEN_EXPIRY);
		const jwtRefresh = signToken({ userId }, REFRESH_TOKEN_EXPIRY);
		request.res.cookie(COOKIE_NAME, jwtAccess, { ...cookieOptions, maxAge: 15 * 60 * 1000 });
		request.res.cookie(REFRESH_COOKIE_NAME, jwtRefresh, { ...cookieOptions, maxAge: 7 * 24 * 60 * 60 * 1000 });

		// Check if user is new (hasn't set up their preferences)
		// A user is considered new if annoy_time is not set (most reliable indicator)
		const isNewUser = !userData.annoy_time;
		
		if (isNewUser) {
			response.redirect('/onboarding');
		} else {
			response.redirect('/dashboard');
		}
	} catch (error) {
		console.error("Error duting token exchange: ", error);
		response.status(500).send("Error: Authentication failed");
	}
});

app.get('/api/me', authenticateToken, async (request, response) => {
	const {data: meData, error: userDataError} = await supabase
		.from('users')
		.select(`github_id, github_username, push_goal, annoy_time, discord_webhook_url, timezone, github_counter(date, push_counter)`)
		.eq('id', request.userId)
		.single();
	if (userDataError) {
		console.error('Error fetching user data:', userDataError);
		return response.status(500).json({"error": "Database error"});
	}
	response.json(meData);
});

app.get('/onboarding', optionalAuth, (request, response) => {
	if (request.userId) {
		response.sendFile(path.join(__dirname, 'onboarding.html'));
	}
	else {
		response.redirect('/');
	}
});

app.get('/dashboard', optionalAuth, (request, response) => {
	if (request.userId) {
		response.sendFile(path.join(__dirname, 'dashboard.html'));
	}
	else {
		response.redirect('/');
	}
});

app.get('/config', (request,response) => {
	response.json({client_id: process.env.GITHUB_CLIENT_ID});
});

app.post('/api/signout', (request, response) => {
	response.clearCookie(COOKIE_NAME, cookieOptions);
	response.clearCookie(REFRESH_COOKIE_NAME, cookieOptions);
	response.json({"message": "Signed out successfully"});
});

app.post('/api/onboarding', authenticateToken, async (request, response) => {
	try {
		const { push_goal, annoy_time, discord_webhook_url, timezone } = request.body;

		// Validate push_goal
		if (!push_goal || push_goal < 1) {
			return response.status(400).json({"error": "push_goal must be a positive integer"});
		}

		// Validate annoy_time format (HH:MM)
		if (!annoy_time) {
			return response.status(400).json({"error": "annoy_time is required"});
		}
		const timeRegex = /^([01]\d|2[0-3]):([0-5]\d)$/;
		if (!timeRegex.test(annoy_time)) {
			return response.status(400).json({"error": "annoy_time must be in HH:MM format (24-hour)"});
		}

		// Validate discord_webhook_url (if provided, must be a valid URL)
		if (discord_webhook_url !== null && discord_webhook_url !== undefined && discord_webhook_url !== '') {
			try {
				new URL(discord_webhook_url);
			} catch (e) {
				return response.status(400).json({"error": "discord_webhook_url must be a valid URL"});
			}
		}

		// Update user settings
		const updateData = {
			push_goal: parseInt(push_goal, 10),
			annoy_time: annoy_time,
			discord_webhook_url: discord_webhook_url || null
		};

		// Only include timezone if provided
		if (timezone !== undefined && timezone !== null && timezone !== '') {
			updateData.timezone = timezone;
		}

		const { data: updatedData, error: updateError } = await supabase
			.from('users')
			.update(updateData)
			.eq('id', request.userId)
			.select()
			.single();

		if (updateError) {
			console.error('Error updating user settings:', updateError);
			return response.status(500).json({"error": "Failed to save settings"});
		}

		response.json({
			"message": "Onboarding completed successfully",
			"data": {
				push_goal: updatedData.push_goal,
				annoy_time: updatedData.annoy_time,
				discord_webhook_url: updatedData.discord_webhook_url,
				timezone: updatedData.timezone
			}
		});
	} catch (error) {
		console.error('Error in onboarding endpoint:', error);
		response.status(500).json({"error": "Internal server error"});
	}
});

app.post('/api/test-webhook', authenticateToken, async (request, response) => {
	try {
		// Get user's Discord webhook URL
		const { data: userData, error: userError } = await supabase
			.from('users')
			.select('discord_webhook_url, github_username')
			.eq('id', request.userId)
			.single();

		if (userError) {
			console.error('Error fetching user data:', userError);
			return response.status(500).json({"error": "Database error"});
		}

		if (!userData.discord_webhook_url) {
			return response.status(400).json({"error": "No Discord webhook URL configured. Please add one in settings."});
		}

		// Send test message to Discord
		const testMessage = `**Test Notification**\n\nHello ${userData.github_username}! This is a test message from your callmeout app. If you see this, your Discord webhook is working correctly! 🎉`;

		try {
			await axios.post(userData.discord_webhook_url, {
				content: testMessage
			});

			response.json({
				"message": "Test notification sent successfully! Check your Discord channel.",
				"success": true
			});
		} catch (discordError) {
			console.error('Error sending Discord webhook:', discordError);
			return response.status(500).json({
				"error": "Failed to send notification to Discord. Please check your webhook URL.",
				"details": discordError.message
			});
		}
	} catch (error) {
		console.error('Error in test webhook endpoint:', error);
		response.status(500).json({"error": "Internal server error"});
	}
});

app.post('/api/settings', authenticateToken, async (request, response) => {
	try {
		const { push_goal, annoy_time, discord_webhook_url, timezone } = request.body;

		// Validate push_goal
		if (push_goal !== undefined) {
			const goalNum = parseInt(push_goal, 10);
			if (isNaN(goalNum) || goalNum < 1) {
				return response.status(400).json({"error": "push_goal must be a positive integer"});
			}
		}

		// Validate annoy_time format (HH:MM)
		if (annoy_time !== undefined && annoy_time !== null && annoy_time !== '') {
			const timeRegex = /^([01]\d|2[0-3]):([0-5]\d)$/;
			if (!timeRegex.test(annoy_time)) {
				return response.status(400).json({"error": "annoy_time must be in HH:MM format (24-hour)"});
			}
		}

		// Validate discord_webhook_url (if provided, must be a valid URL)
		if (discord_webhook_url !== undefined && discord_webhook_url !== null && discord_webhook_url !== '') {
			try {
				new URL(discord_webhook_url);
			} catch (e) {
				return response.status(400).json({"error": "discord_webhook_url must be a valid URL"});
			}
		}

		// Build update object with only provided fields
		const updateData = {};
		if (push_goal !== undefined) {
			updateData.push_goal = parseInt(push_goal, 10);
		}
		if (annoy_time !== undefined) {
			updateData.annoy_time = annoy_time || null;
		}
		if (discord_webhook_url !== undefined) {
			updateData.discord_webhook_url = discord_webhook_url || null;
		}
		if (timezone !== undefined && timezone !== null && timezone !== '') {
			updateData.timezone = timezone;
		}

		// If no fields to update, return error
		if (Object.keys(updateData).length === 0) {
			return response.status(400).json({"error": "No valid fields to update"});
		}

		// Update user settings
		const { data: updatedData, error: updateError } = await supabase
			.from('users')
			.update(updateData)
			.eq('id', request.userId)
			.select()
			.single();

		if (updateError) {
			console.error('Error updating user settings:', updateError);
			return response.status(500).json({"error": "Failed to update settings"});
		}

		response.json({
			"message": "Settings updated successfully",
			"data": {
				push_goal: updatedData.push_goal,
				annoy_time: updatedData.annoy_time,
				discord_webhook_url: updatedData.discord_webhook_url,
				timezone: updatedData.timezone
			}
		});
	} catch (error) {
		console.error('Error in settings endpoint:', error);
		response.status(500).json({"error": "Internal server error"});
	}
});

// Cron job function (can be called by Vercel Cron Jobs or node-cron locally)
async function checkPushGoals() {
	const today = new Date().toISOString().split('T')[0];
	const now = new Date().toTimeString().slice(0, 5); // "HH:MM" format in server time (UTC)
	console.log(`Running cron job at ${now}...`);

	// Get ALL users whose notification time has passed (not just those who pushed)
	const {data: users, error: usersError} = await supabase
		.from('users')
		.select('id, push_goal, discord_webhook_url, annoy_time, timezone')
		.not('discord_webhook_url', 'is', null)
		.not('annoy_time', 'is', null);

	if (usersError || !users?.length) {
		console.log(usersError ? `Error: ${usersError.message}` : 'No users to notify at this time');
		return;
	}

	// Get today's push counters for these users
	const {data: counters} = await supabase
		.from('github_counter')
		.select('id, user_id, push_counter, is_job_done')
		.eq('date', today)
		.in('user_id', users.map(u => u.id));

	const counterMap = new Map(counters?.map(c => [c.user_id, c]));
	console.log(`Checking ${users.length} user(s)...`);

	for (const user of users) {
		const counter = counterMap.get(user.id);
		if (counter?.is_job_done) continue; // Already notified today

		// Convert current time to user's timezone
		const userTimezone = user.timezone || 'UTC';
		const now = new Date();
		const options = {
			timeZone: userTimezone,
			hour: '2-digit',
			minute: '2-digit',
			hour12: false
		};
		const userTimeString = now.toLocaleTimeString('en-US', options); // "HH:MM" in user's timezone
		
		// Compare user's annoy_time with the current time in their timezone
		const shouldNotify = userTimeString >= user.annoy_time;

		if (!shouldNotify) {
			console.log(`User ${user.id} not yet at annoy time. Local time: ${userTimeString}, annoy_time: ${user.annoy_time}`);
			continue;
		}

		const pushCount = counter?.push_counter || 0;
		const goalMet = pushCount >= user.push_goal;

		if (goalMet && counter) {
			await supabase.from('github_counter').update({is_job_done: true}).eq('id', counter.id);
		}

		await axios.post(user.discord_webhook_url, {
			content: goalMet 
				? 'Congratulations! You have achieved your *git push* goal for today 🎉' 
				: 'push kar bc'
		});
		console.log(`Sent notification to user ${user.id}. Push count: ${pushCount}, Goal met: ${goalMet}`);
	}
	console.log('Cron job completed');
}

// API endpoint for Vercel Cron Jobs
app.get('/api/cron', async (request, response) => {
	// Optional: Add authentication to prevent unauthorized access
	const cronSecret = request.headers['x-cron-secret'] || request.query.secret;
	if (process.env.CRON_SECRET && cronSecret !== process.env.CRON_SECRET) {
		return response.status(401).json({"error": "Unauthorized"});
	}
	
	try {
		await checkPushGoals();
		response.json({"message": "Cron job executed successfully"});
	} catch (error) {
		console.error('Cron job error:', error);
		response.status(500).json({"error": "Cron job failed"});
	}
});

// Only use node-cron when running locally (not on Vercel)
if (process.env.VERCEL !== '1') {
	cron.schedule('*/5 * * * *', checkPushGoals);
}

// Export for Vercel serverless functions
export default app;

// Only start server if running locally (not on Vercel)
if (process.env.VERCEL !== '1') {
	const PORT = process.env.PORT || 6900;
	app.listen(PORT, () => {
		console.log(`Server is active on port ${PORT}`);
	});
}
