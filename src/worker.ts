import { Hono } from 'hono';
import * as jose from 'jose';

interface Env {
  KV: KVNamespace;
  DISCORD_TOKEN?: string;
  CLIENT_ID: string;
  CLIENT_SECRET: string;
  REDIRECT_URL: string;
  SERVERS_TO_CHECK_ROLES?: string;
}

interface KeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

interface KeyPairJson {
  publicKey: JsonWebKey;
  privateKey: JsonWebKey;
}

interface DiscordTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token: string;
  scope: string;
}

interface DiscordUserInfo {
  id: string;
  username: string;
  discriminator?: string;
  verified: boolean;
  email: string;
  global_name?: string;
}

interface DiscordGuild {
  id: string;
}

interface DiscordMemberResponse {
  roles: string[];
}

const algorithm: RsaHashedKeyGenParams = {
  name: 'RSASSA-PKCS1-v1_5',
  modulusLength: 2048,
  publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
  hash: { name: 'SHA-256' },
};

const importAlgo: RsaHashedImportParams = {
  name: 'RSASSA-PKCS1-v1_5',
  hash: { name: 'SHA-256' },
};

async function loadOrGenerateKeyPair(KV: KVNamespace): Promise<KeyPair> {
  const keyPairJson = await KV.get('keys', { type: 'json' }) as KeyPairJson | null;

  if (keyPairJson !== null) {
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      keyPairJson.publicKey,
      importAlgo,
      true,
      ['verify']
    );
    const privateKey = await crypto.subtle.importKey(
      'jwk',
      keyPairJson.privateKey,
      importAlgo,
      true,
      ['sign']
    );

    return { publicKey, privateKey };
  } else {
    const generatedKeyPair = await crypto.subtle.generateKey(
      algorithm,
      true,
      ['sign', 'verify']
    ) as CryptoKeyPair;

    await KV.put(
      'keys',
      JSON.stringify({
        privateKey: await crypto.subtle.exportKey('jwk', generatedKeyPair.privateKey),
        publicKey: await crypto.subtle.exportKey('jwk', generatedKeyPair.publicKey),
      })
    );

    return {
      publicKey: generatedKeyPair.publicKey,
      privateKey: generatedKeyPair.privateKey,
    };
  }
}

const app = new Hono<{ Bindings: Env }>();

app.get('/authorize/:scopemode', async (c) => {
  if (
    c.req.query('client_id') !== c.env.CLIENT_ID ||
    c.req.query('redirect_uri') !== c.env.REDIRECT_URL ||
    !['guilds', 'email'].includes(c.req.param('scopemode'))
  ) {
    return c.text('Bad request.', 400);
  }

  const params = new URLSearchParams({
    client_id: c.env.CLIENT_ID,
    redirect_uri: c.env.REDIRECT_URL,
    response_type: 'code',
    scope: c.req.param('scopemode') === 'guilds' ? 'identify email guilds' : 'identify email',
    state: c.req.query('state') || '',
    prompt: 'none',
  }).toString();

  return c.redirect('https://discord.com/oauth2/authorize?' + params);
});

app.post('/token', async (c) => {
  const body = await c.req.parseBody();
  const code = body['code'] as string;
  
  const params = new URLSearchParams({
    client_id: c.env.CLIENT_ID,
    client_secret: c.env.CLIENT_SECRET,
    redirect_uri: c.env.REDIRECT_URL,
    code: code,
    grant_type: 'authorization_code',
    scope: 'identify email',
  }).toString();

  const tokenResponse = await fetch('https://discord.com/api/v10/oauth2/token', {
    method: 'POST',
    body: params,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  }).then((res) => res.json()) as DiscordTokenResponse;

  if (!tokenResponse.access_token) return new Response('Bad request.', { status: 400 });

  const userInfo = (await fetch('https://discord.com/api/v10/users/@me', {
    headers: {
      Authorization: `Bearer ${tokenResponse.access_token}`,
    },
  }).then((res) => res.json())) as DiscordUserInfo;

  if (!userInfo.verified) return c.text('Bad request.', 400);

  let servers: string[] = [];

  const serverResp = await fetch('https://discord.com/api/v10/users/@me/guilds', {
    headers: {
      Authorization: `Bearer ${tokenResponse.access_token}`,
    },
  });

  if (serverResp.status === 200) {
    const serverJson = (await serverResp.json()) as DiscordGuild[];
    servers = serverJson.map((item) => item.id);
  }

  const roleClaims: Record<string, string[]> = {};

  if (c.env.DISCORD_TOKEN && c.env.SERVERS_TO_CHECK_ROLES) {
    const serversToCheck = c.env.SERVERS_TO_CHECK_ROLES.split(',');
    await Promise.all(
      serversToCheck.map(async (guildId) => {
        if (servers.includes(guildId)) {
          const memberResp = await fetch(
            `https://discord.com/api/v10/guilds/${guildId}/members/${userInfo.id}`,
            {
              headers: {
                Authorization: `Bot ${c.env.DISCORD_TOKEN}`,
              },
            }
          );
          const memberJson = await memberResp.json() as DiscordMemberResponse;
          roleClaims[`roles:${guildId}`] = memberJson.roles;
        }
      })
    );
  }

  let preferred_username = userInfo.username;

  if (userInfo.discriminator && userInfo.discriminator !== '0') {
    preferred_username += `#${userInfo.discriminator}`;
  }

  let displayName = userInfo.global_name ?? userInfo.username;

  const idToken = await new jose.SignJWT({
    iss: 'https://cloudflare.com',
    aud: c.env.CLIENT_ID,
    preferred_username,
    ...userInfo,
    ...roleClaims,
    email: userInfo.email,
    global_name: userInfo.global_name,
    name: displayName,
    guilds: servers,
  })
    .setProtectedHeader({ alg: 'RS256' })
    .setExpirationTime('1h')
    .setAudience(c.env.CLIENT_ID)
    .sign((await loadOrGenerateKeyPair(c.env.KV)).privateKey);

  return c.json({
    ...tokenResponse,
    scope: 'identify email',
    id_token: idToken,
  });
});

app.get('/jwks.json', async (c) => {
  const publicKey = (await loadOrGenerateKeyPair(c.env.KV)).publicKey;
  return c.json({
    keys: [
      {
        alg: 'RS256',
        kid: 'jwtRS256',
        ...(await crypto.subtle.exportKey('jwk', publicKey)),
      },
    ],
  });
});

export default app;
