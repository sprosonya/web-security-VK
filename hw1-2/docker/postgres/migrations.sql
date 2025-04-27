CREATE TABLE requests (
                          id SERIAL PRIMARY KEY,
                          method VARCHAR(10) NOT NULL,
                          url TEXT NOT NULL,
                          get_params JSONB,
                          post_params JSONB,
                          headers JSONB,
                          cookies JSONB,
                          body TEXT,
);

CREATE TABLE responses (
                           id SERIAL PRIMARY KEY,
                           code INTEGER NOT NULL,
                           message VARCHAR(100) NOT NULL,
                           headers JSONB,
                           body TEXT,
                           req_id INTEGER REFERENCES requests(id) ON DELETE CASCADE,
);
