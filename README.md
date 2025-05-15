# aibarf

An open-source, minimalist image hosting platform built with:

- Cloudflare Workers (serverless backend)
- Cloudflare D1 (SQL database for users, metadata, comments)
- R2 (for storing image files)
- Cloudflare Pages (static frontend)
- mailgun

## Features

- User signup & login (email + password)
- Image upload + description
- Commenting & likes
- Sorting & filtering
- 100% serverless & scalable

## Getting Started

```bash
npm install -g wrangler
wrangler dev
