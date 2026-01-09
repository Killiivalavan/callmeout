import express from "express";
import axios from "axios";
import "dotenv/config";
import {createClient} from "@supabase/supabase-js";
import session from "express-session";
import path from 'path';
import crypto from "crypto";
import cron from 'node-cron';

const app = express();
app.use(express.static('.'));
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
app.use(session({
	secret: process.env.SESSION_SECRET,
	resave: false,
	saveUninitialized: false
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
	response.sendFile(path.resolve('index.html'));
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
		response.redirect('/dashboard');
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

app.get('/dashboard', (request, response) => {
	if (request.session.userId) {
		response.sendFile(path.resolve('dashboard.html'));
	}
	else {
		response.redirect('/');
	}
});

app.get('/config', (request,response) => {
	response.json({client_id: process.env.GITHUB_CLIENT_ID});
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

cron.schedule('*/5 * * * *', async () => {
	const today = new Date().toISOString().split('T')[0];
	const now = new Date().toLocaleTimeString('en-US', {hour12: false});
	console.log('Running cron job to check push goals...');
	const {data:userCronCheck, error} = await supabase
		.from('github_counter')
		.select(`id, push_counter, users(push_goal, discord_webhook_url, annoy_time)`)
		.eq('date', today)
		.eq('is_job_done', false);
	if (error) {
		console.error('Cron job failed to fetch users', error);
		return;
	};
	if (!userCronCheck || userCronCheck.length == 0) {
		console.log('No users to check. Cron Job completed');
		return;
	};
	console.log(`Found ${userCronCheck.length} user(s) to check`);
	for (let item of userCronCheck) {
		if (item.push_counter >= item.users.push_goal) {
			await supabase 
				.from('github_counter')
				.update({is_job_done: true})
				.eq('id', item.id);
			await axios.post(item.users.discord_webhook_url, {
				content: 'Congratulations! You have acheived your *git push* goal for today'
			});
		} else {
			if (now >= item.users.annoy_time) {
				await axios.post(item.users.discord_webhook_url, {
					content: 'push kar bc'
				});
			};
		}
	}
});

app.listen(6900, ()=> {
	console.log('Server is active on port 6900');
});

