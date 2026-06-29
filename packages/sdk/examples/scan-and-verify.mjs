import { SecureAiClient } from '../dist/index.js'

const apiKey = process.env.SECUREAI_API_KEY
const secureai = new SecureAiClient({ apiKey })

const result = await secureai.scan({
  sourceUrl: process.argv[2] ?? 'https://github.com/danielwjh04/SecureAI',
})

const verification = await secureai.verify(result.proof)

process.stdout.write(
  JSON.stringify(
    {
      verdict: result.verdict,
      headHash: result.proof.headHash,
      verification,
    },
    null,
    2,
  ),
)
