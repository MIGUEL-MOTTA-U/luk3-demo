// src/server.ts
import express, { type Request, type Response, type NextFunction } from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import axios from 'axios';
import dotenv from 'dotenv';
import zxcvbn from 'zxcvbn';
import cors from 'cors';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const HIBP_KEY = process.env.HIBP_API_KEY;
if (!HIBP_KEY) {
  console.error('Falta la clave HIBP_API_KEY en .env');
  process.exit(1);
}

// Middlewares
app.use(helmet());
const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') ?? [];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('No permitido por CORS'));
    }
  },
  methods: ['GET', 'POST'],
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(rateLimit({ windowMs: 1 * 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false }));// Limitar a 100 peticiones por minuto

app.post('/api/breaches', async (req: Request, res: Response): Promise<void> => {
  const { email } = req.body;
  if (!email) {
    res.status(400).json({ error: 'Email es requerido' });
    return;
  }
  try {
    const { data } = await axios.get(
      `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
      { headers: { 'hibp-api-key': HIBP_KEY, Accept: 'application/json' } }
    );
    res.json(data);
  } catch (err: unknown) {
    const e = err as { response?: { status: number }; message: string };
    if (e.response?.status === 404) {
      res.json([]);
    } else {
      console.error(e.message);
      res.status(500).json({ error: 'Error en API HIBP' });
    }
  }
});

app.get('/api/health', (_req: Request, res: Response) => {
    res.json({ status: 'OK' });
});

// Ruta para analizar contraseña
app.post('/api/password', async (req: Request, res: Response): Promise<void> => {
  const { password } = req.body;
  if (!password) {
    res.status(400).json({ error: 'Password es requerido' });
    return;
  }

  const strength = zxcvbn(password);
  const feedback = strength.feedback;
  const crypto = await import('node:crypto');
  const hash = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
  const prefix = hash.slice(0, 5);

  try {
    const rangeRes = await axios.get(`https://api.pwnedpasswords.com/range/${prefix}`);
    const lines: string[] = rangeRes.data.split('\r\n');
    const match = lines.find(line => line.split(':')[0] === hash.slice(5));
    const count = match ? Number.parseInt(match.split(':')[1], 10) : 0;
    res.json({ strength: { score: strength.score, suggestions: feedback.suggestions, warning: feedback.warning || null }, pwnedCount: count });
  } catch (err: unknown) {
    const e = err as Error;
    console.error(e.message);
    res.status(500).json({ error: 'Error al comprobar pwned passwords' });
  }
});

// Middleware genérico de errores
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Error interno del servidor' });
});

app.listen(PORT, () => console.log(`Servidor corriendo en http://localhost:${PORT}`));
