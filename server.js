import express from "express";
import axios from "axios";
import "dotenv/config";
import {createClient} from "@supabase/supabase-js";
import session from "express-session";
import path from 'path';
import crypto from "crypto";

const app = express();
app.use(express.static('.'));
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
app.use(session({
	secret: process.env.SESSION_SECRET,
	resave: false,
	saveUninitialized: false
}));

app.get('/', (request, response) => {
	response.send("Hello World");
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
			.select(`github_id, github_username, push_goal, github_counter(date, push_counter)`)
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
	console.log('Webhook Signature varified successfully');
	const pushEvent = JSON.parse(request.body.toString());
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
			console.error('Unable to upsert data');
			return response.status(500).send("Data not updated")
	}
	else {
		return response.status(200).send('Webhook recieved successfully')
	};
});

app.get('/config', (request,response) => {
	response.json({client_id: process.env.GITHUB_CLIENT_ID});
});

app.listen(6900, ()=> {
	console.log('Server is active on port 6900');
});

