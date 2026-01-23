import type { NextApiRequest, NextApiResponse } from 'next';

const OUTLAYER_API_URL = process.env.NEXT_PUBLIC_OUTLAYER_API_URL || 'https://outlayer.xyz';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  // Get the path from the catch-all route
  const { path } = req.query;
  const targetPath = Array.isArray(path) ? path.join('/') : path;
  const targetUrl = `${OUTLAYER_API_URL}/${targetPath}`;

  try {
    // Forward the request to OutLayer API
    const response = await fetch(targetUrl, {
      method: req.method,
      headers: {
        'Content-Type': 'application/json',
        // Forward the Payment Key header
        ...(req.headers['x-payment-key'] && {
          'X-Payment-Key': req.headers['x-payment-key'] as string,
        }),
      },
      body: req.method !== 'GET' ? JSON.stringify(req.body) : undefined,
    });

    const data = await response.text();

    // Forward the response
    res.status(response.status);

    // Try to parse as JSON
    try {
      res.json(JSON.parse(data));
    } catch {
      res.send(data);
    }
  } catch (error: any) {
    console.error('Proxy error:', error);
    res.status(500).json({ error: error.message || 'Proxy error' });
  }
}

export const config = {
  api: {
    bodyParser: true,
  },
};
