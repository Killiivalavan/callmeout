import express from "express";
import axios from "axios";
import "dotenv/config";
import {createClient} from "@supabase/supabase-js";
import session from "express-session";
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from "crypto";
import cron from 'node-cron';

// Get __dirname equivalent for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Trust proxy (important for Render and other hosting services)
app.set('trust proxy', 1);

// Serve static files from public folder (Vercel serves this automatically)
// This is for local development - Vercel serves /public automatically
app.use(express.static(path.join(__dirname, 'public')));

// Validate required environment variables
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_ANON_KEY) {
	console.error('Missing required Supabase environment variables');
}

const supabase = createClient(
	process.env.SUPABASE_URL || '', 
	process.env.SUPABASE_ANON_KEY || ''
);

// Session configuration
// For Render: Use in-memory sessions (works fine since it's a persistent server, not serverless)
app.use(session({
	secret: process.env.SESSION_SECRET || 'fallback-secret-change-in-production',
	resave: false,
	saveUninitialized: false,
	name: 'callmeout.sid',
	cookie: {
		maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days in milliseconds
		httpOnly: true,
		// Only use secure cookies if explicitly on HTTPS (Render uses HTTPS by default)
		secure: process.env.FORCE_SECURE_COOKIES === 'true',
		sameSite: 'lax',
		// Ensure cookie works across subdomains if needed
		domain: undefined // Let browser handle domain automatically
	}
}));

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
	if (request.session.userId) {
		response.redirect('/dashboard');
	} else {
		response.sendFile(path.join(__dirname, 'index.html'));
	}
});

app.get('/callback', async (request,response) => {
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
		request.session.userId = userData.id;
		
		// Save session before redirect
		request.session.save((err) => {
			if (err) {
				console.error('Error saving session:', err);
				return response.status(500).send("Error: Failed to save session");
			}
			
			// Check if user is new (hasn't set up their preferences)
			// A user is considered new if annoy_time is not set (most reliable indicator)
			const isNewUser = !userData.annoy_time;
			
			if (isNewUser) {
				response.redirect('/onboarding');
			} else {
				response.redirect('/dashboard');
			}
		});
	} catch (error) {
		console.error("Error duting token exchange: ", error);
		response.status(500).send("Error: Authentication failed");
	}
});

app.get('/api/me', async (request,response) => {
	if (request.session.userId) {
		const {data: meData,error: userDataError} = await supabase
			.from('users')
			.select(`github_id, github_username, push_goal, annoy_time, discord_webhook_url, github_counter(date, push_counter)`)
			.eq('id', request.session.userId)
			.single();
		if (userDataError) {
			console.error('Error fetching user data:', userDataError);
			return response.status(500).json({"error": "Database error"});
		}
		response.json(meData);
	}
	else {
		response.status(401).json({"error": "401 Unauthorized"});
	}
});

app.get('/onboarding', (request, response) => {
	if (request.session.userId) {
		response.sendFile(path.join(__dirname, 'onboarding.html'));
	}
	else {
		response.redirect('/');
	}
});

app.get('/dashboard', (request, response) => {
	if (request.session.userId) {
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
	request.session.destroy((err) => {
		if (err) {
			console.error('Error destroying session:', err);
			return response.status(500).json({"error": "Failed to sign out"});
		}
		// Clear the session cookie with same settings as session
		response.clearCookie('callmeout.sid', {
			httpOnly: true,
			secure: process.env.NODE_ENV === 'production',
			sameSite: 'lax'
		});
		response.json({"message": "Signed out successfully"});
	});
});

app.post('/api/onboarding', async (request, response) => {
	if (!request.session.userId) {
		return response.status(401).json({"error": "401 Unauthorized"});
	}

	try {
		const { push_goal, annoy_time, discord_webhook_url } = request.body;

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

		const { data: updatedData, error: updateError } = await supabase
			.from('users')
			.update(updateData)
			.eq('id', request.session.userId)
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
				discord_webhook_url: updatedData.discord_webhook_url
			}
		});
	} catch (error) {
		console.error('Error in onboarding endpoint:', error);
		response.status(500).json({"error": "Internal server error"});
	}
});

app.post('/api/test-webhook', async (request, response) => {
	if (!request.session.userId) {
		return response.status(401).json({"error": "401 Unauthorized"});
	}

	try {
		// Get user's Discord webhook URL
		const { data: userData, error: userError } = await supabase
			.from('users')
			.select('discord_webhook_url, github_username')
			.eq('id', request.session.userId)
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

app.post('/api/settings', async (request, response) => {
	if (!request.session.userId) {
		return response.status(401).json({"error": "401 Unauthorized"});
	}

	try {
		const { push_goal, annoy_time, discord_webhook_url } = request.body;

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

		// If no fields to update, return error
		if (Object.keys(updateData).length === 0) {
			return response.status(400).json({"error": "No valid fields to update"});
		}

		// Update user settings
		const { data: updatedData, error: updateError } = await supabase
			.from('users')
			.update(updateData)
			.eq('id', request.session.userId)
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
				discord_webhook_url: updatedData.discord_webhook_url
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
	const now = new Date().toTimeString().slice(0, 5); // "HH:MM" format
	console.log(`Running cron job at ${now}...`);

	// Get ALL users whose notification time has passed (not just those who pushed)
	const {data: users, error: usersError} = await supabase
		.from('users')
		.select('id, push_goal, discord_webhook_url, annoy_time')
		.not('discord_webhook_url', 'is', null)
		.not('annoy_time', 'is', null)
		.lte('annoy_time', now);

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

