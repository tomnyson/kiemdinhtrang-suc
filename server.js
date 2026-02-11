import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import multer from 'multer';
import crypto from 'crypto';
import { createClient } from '@supabase/supabase-js';
import path from 'path';
import { fileURLToPath } from 'url';

const {
  PORT = 3000,
  SUPABASE_URL,
  SUPABASE_ANON_KEY,
  SUPABASE_SERVICE_ROLE_KEY,
  SUPABASE_BUCKET = 'product-images',
  SIGNED_URL_EXPIRES_IN = 31536000,
  ADMIN_EMAILS = ''
} = process.env;
console.log(process.env)

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in environment.');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false }
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors({
  origin: true,
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.static(__dirname));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }
});

const sanitizeFilename = (name) => name.replace(/[^a-zA-Z0-9._-]/g, '_');
const adminEmailSet = new Set(
  String(ADMIN_EMAILS)
    .split(',')
    .map((email) => email.trim().toLowerCase())
    .filter(Boolean)
);

async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing Authorization bearer token.' });
  }

  const token = authHeader.slice(7).trim();
  if (!token) {
    return res.status(401).json({ error: 'Missing access token.' });
  }

  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data?.user) {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }

  req.user = data.user;
  return next();
}

function userHasAdminRole(user) {
  if (!user) return false;
  const email = String(user.email || '').toLowerCase();
  if (adminEmailSet.size > 0 && email && adminEmailSet.has(email)) return true;

  const appRole = user.app_metadata?.role;
  const userRole = user.user_metadata?.role;
  if (appRole === 'admin' || userRole === 'admin') return true;

  const appRoles = user.app_metadata?.roles;
  const userRoles = user.user_metadata?.roles;
  if (Array.isArray(appRoles) && appRoles.includes('admin')) return true;
  if (Array.isArray(userRoles) && userRoles.includes('admin')) return true;

  return false;
}

async function requireAdmin(req, res, next) {
  await requireAuth(req, res, async () => {
    if (!userHasAdminRole(req.user)) {
      return res.status(403).json({ error: 'Admin access required.' });
    }
    return next();
  });
}

const signedUrlExpiresIn = Number(SIGNED_URL_EXPIRES_IN) || 31536000;

async function getSignedImageUrl(imagePath) {
  if (!imagePath) return null;
  const { data, error } = await supabase.storage
    .from(SUPABASE_BUCKET)
    .createSignedUrl(imagePath, signedUrlExpiresIn);

  if (error) {
    console.warn(`Failed to sign image ${imagePath}: ${error.message}`);
    return null;
  }
  return data.signedUrl;
}

async function uploadImage(file) {
  if (!file) return { imageUrl: null, imagePath: null };

  const extension = file.originalname.includes('.')
    ? file.originalname.split('.').pop()
    : 'bin';
  const safeName = sanitizeFilename(file.originalname || `image.${extension}`);
  const fileName = `${crypto.randomUUID()}-${safeName}`;
  const filePath = `products/${fileName}`;

  const { error: uploadError } = await supabase.storage
    .from(SUPABASE_BUCKET)
    .upload(filePath, file.buffer, {
      contentType: file.mimetype,
      upsert: false
    });

  if (uploadError) {
    throw new Error(`Upload failed: ${uploadError.message}`);
  }

  const imageUrl = await getSignedImageUrl(filePath);
  return { imageUrl, imagePath: filePath };
}

async function deleteImage(imagePath) {
  if (!imagePath) return;
  const { error } = await supabase.storage.from(SUPABASE_BUCKET).remove([imagePath]);
  if (error) {
    console.warn(`Failed to delete image ${imagePath}: ${error.message}`);
  }
}

async function resolveImageUrl(record) {
  if (!record) return record;
  if (!record.image_path) return record;
  const signedUrl = await getSignedImageUrl(record.image_path);
  return { ...record, image_url: signedUrl || record.image_url || null };
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/api/status', (req, res) => {
  res.json({ status: 'ok', service: 'products-api' });
});

app.get('/config', (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
    return res.status(500).json({ error: 'Missing SUPABASE_URL or SUPABASE_ANON_KEY.' });
  }
  return res.json({
    supabaseUrl: SUPABASE_URL,
    supabaseAnonKey: SUPABASE_ANON_KEY
  });
});

app.get(['/admin', '/admin.html'], (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// Public endpoint to get certificate by name (certId) - no auth required
app.get('/certificate/:name', async (req, res) => {
  const { name } = req.params;
  const { data, error } = await supabase
    .from('products')
    .select('*')
    .eq('name', name)
    .single();

  if (error) return res.status(404).json({ error: 'Certificate not found.' });
  return res.json(await resolveImageUrl(data));
});

// Public endpoint to get all certificate names for random selection
app.get('/certificates/names', async (req, res) => {
  const { data, error } = await supabase
    .from('products')
    .select('name')
    .order('created_at', { ascending: false });

  if (error) return res.status(500).json({ error: error.message });
  return res.json(data.map(p => p.name));
});

app.get('/products', requireAdmin, async (req, res) => {
  const { data, error } = await supabase
    .from('products')
    .select('*')
    .order('created_at', { ascending: false });

  if (error) return res.status(500).json({ error: error.message });
  const withUrls = await Promise.all(data.map(resolveImageUrl));
  return res.json(withUrls);
});

app.get('/products/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { data, error } = await supabase
    .from('products')
    .select('*')
    .eq('id', id)
    .single();

  if (error) return res.status(404).json({ error: error.message });
  return res.json(await resolveImageUrl(data));
});

app.post('/products', requireAdmin, upload.single('image'), async (req, res) => {
  try {
    const { name, description = null, price } = req.body;

    if (!name || String(name).trim() === '') {
      return res.status(400).json({ error: 'Name is required.' });
    }

    const parsedPrice = Number(price);
    if (Number.isNaN(parsedPrice) || parsedPrice < 0) {
      return res.status(400).json({ error: 'Price must be a non-negative number.' });
    }

    const { imageUrl, imagePath } = await uploadImage(req.file);

    const { data, error } = await supabase
      .from('products')
      .insert({
        name: String(name).trim(),
        description: description ? String(description).trim() : null,
        price: parsedPrice,
        image_url: imageUrl,
        image_path: imagePath
      })
      .select('*')
      .single();

    if (error) return res.status(500).json({ error: error.message });
    return res.status(201).json(data);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.put('/products/:id', requireAdmin, upload.single('image'), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, price } = req.body;

    const { data: existing, error: existingError } = await supabase
      .from('products')
      .select('*')
      .eq('id', id)
      .single();

    if (existingError || !existing) {
      return res.status(404).json({ error: 'Product not found.' });
    }

    const updates = {};
    if (name !== undefined) {
      if (String(name).trim() === '') {
        return res.status(400).json({ error: 'Name cannot be empty.' });
      }
      updates.name = String(name).trim();
    }

    if (description !== undefined) {
      updates.description = description ? String(description).trim() : null;
    }

    if (price !== undefined) {
      const parsedPrice = Number(price);
      if (Number.isNaN(parsedPrice) || parsedPrice < 0) {
        return res.status(400).json({ error: 'Price must be a non-negative number.' });
      }
      updates.price = parsedPrice;
    }

    if (req.file) {
      await deleteImage(existing.image_path);
      const { imageUrl, imagePath } = await uploadImage(req.file);
      updates.image_url = imageUrl;
      updates.image_path = imagePath;
    } else if (existing.image_path) {
      updates.image_url = await getSignedImageUrl(existing.image_path);
    }

    const { data, error } = await supabase
      .from('products')
      .update(updates)
      .eq('id', id)
      .select('*')
      .single();

    if (error) return res.status(500).json({ error: error.message });
    return res.json(data);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.delete('/products/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const { data: existing, error: existingError } = await supabase
      .from('products')
      .select('*')
      .eq('id', id)
      .single();

    if (existingError || !existing) {
      return res.status(404).json({ error: 'Product not found.' });
    }

    await deleteImage(existing.image_path);

    const { error } = await supabase
      .from('products')
      .delete()
      .eq('id', id);

    if (error) return res.status(500).json({ error: error.message });
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
