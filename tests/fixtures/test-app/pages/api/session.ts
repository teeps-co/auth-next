import { NextApiRequest, NextApiResponse } from 'next';

export default function sessionHandler(req: NextApiRequest, res: NextApiResponse): void {
  const json = (global as any).getSession(req, res);
  res.status(200).json(json);
}
