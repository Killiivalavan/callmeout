CREATE table users (
	id BIGSERIAL PRIMARY KEY,
	github_id BIGINT UNIQUE NOT NULL,
	github_username TEXT NOT NULL,
	github_access_token TEXT,
	push_goal INT NOT NULL DEFAULT 1 CHECK ( push_goal>0 ),
	discord_webhook_url TEXT
);

CREATE table github_counter (
	id BIGSERIAL PRIMARY KEY,
	user_id BIGINT NOT NULL REFERENCES users(id),
	date date NOT NULL,
	push_counter INT NOT NULL DEFAULT 1,
	UNIQUE (user_id, date)
);


