# Vulner
Get a complete **Digital Health Check** for your website. 

Our platform scans your website for *security vulnerabilities*, *performance bottlenecks*, *SEO issues*, and *accessibility compliance*, providing clear, actionable reports to help you improve.

# Installation

Step 1: Install the lighthouse dependency
```
npm install -g lighthouse
```

Step 2: Install the necessary packages
```
pip install -r requirements.txt
```

Step 3: Install redis to implement a queueing system

```
brew install redis
```

Step 4: Setup environment variables. If you choose to use any service other than brevo, you may change the smtp address in app.py. Similarly, if you want to use any other LLM API, update the API KEY and url accordingly.

```
export EMAIL_USER="<your_brevo_login_email>"
export EMAIL_PASS="<your_brevo_master_password>"
export PERPLEXITY_API_KEY="<your_perplexity_api_key>"
```

# Execution

You will require three terminal tabs open for the whole project to work.

First Tab: Start the flask server
```
python app.py
```

Second Tab: Start the redis server
```
redis-server
```

Third Tab: Start the Redis Queue Worker
```
rq worker
```

Next, you may open the website in the browser, the link is available in the First Terminal Tab and enjoy!