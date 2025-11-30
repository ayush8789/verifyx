// backend/lib/checker.js
// Upgraded VerifyX rule-based detector
// Returns detailed reasons + numeric score (0-100) and level (green/yellow/red)

const suspiciousTLDs = new Set(['xyz','info','top','bit','club','loan','online','site']);
const freeEmailPatterns = /\b(gmail|yahoo|hotmail|outlook|rediff|yandex|protonmail)\b/i;

const paymentKeywords = [
  'processing fee','registration fee','security deposit','pay before','pay to',
  'refund','transfer','upi','bank account','account number','pay via','paytm',
  'paytm','gpay','phonepe','deposit','send money','send ₹','send rs','send rs.',
  'send inr','pay now','pay ₹','pay rs'
];

const scamPhrases = [
  'work from home','earn ₹','earn rs','earn per day','no interview','join immediately',
  'urgent hiring','limited seats','only','guaranteed','100% placement','get paid daily'
];

const phoneRegex = /(?:\+91|91)?[\s\-]?(?:[6-9]\d{9}|\d{3}[\-]\d{3}[\-]\d{4})/g;
const upiRegex = /\b[\w.\-]{2,}@[a-zA-Z]{2,}\b/g; // basic UPI id like name@okicici
const emailRegex = /[\w.+-]+@([\w-]+\.)+[\w-]{2,}/g;

// helper: compute hostname entropy-ish (measure of randomness)
function hostnameEntropy(hostname) {
  if(!hostname) return 0;
  const s = hostname.replace(/\./g,'');
  const freq = {};
  for(const c of s) freq[c] = (freq[c]||0) + 1;
  const len = s.length;
  let ent = 0;
  for(const k in freq){
    const p = freq[k] / len;
    ent -= p * Math.log2(p);
  }
  // normalize roughly to 0-4 range
  return Math.min(4, ent);
}

// helper: count occurrences of any word list
function countMatches(text, list) {
  if(!text) return 0;
  const lower = text.toLowerCase();
  let count = 0;
  for(const k of list) if(lower.includes(k)) count++;
  return count;
}

// main analyze function
function analyze(type='text', value=''){
  const reasons = [];
  const lowered = (value || '').toString().trim();
  let score = 0;
  const features = {};

  // 1) detect emails
  const emails = (lowered.match(emailRegex) || []);
  features.emailCount = emails.length;
  if(emails.length > 0) {
    const freeEmails = emails.filter(e => freeEmailPatterns.test(e));
    if(freeEmails.length > 0) {
      reasons.push(`Using free email provider (${freeEmails.slice(0,2).join(', ')}) — corporate emails are more trustworthy`);
      score += 20;
      features.freeEmailCount = freeEmails.length;
    }
  }

  // 2) detect phone numbers
  const phones = (lowered.match(phoneRegex) || []);
  features.phoneCount = phones.length;
  if(phones.length > 0) {
    reasons.push(`Phone/WhatsApp number detected (${phones[0]}) — many scams ask to contact via messaging`);
    score += 12;
  }

  // 3) detect UPI ids
  const upis = (lowered.match(upiRegex) || []);
  features.upiCount = upis.length;
  if(upis.length > 0) {
    reasons.push(`UPI/payment id detected (${upis[0]}) — requests for direct payment are high-risk`);
    score += 30;
  }

  // 4) payment/payment-like keyword detection
  const payMatches = countMatches(lowered, paymentKeywords);
  features.paymentKeywordCount = payMatches;
  if(payMatches > 0) {
    reasons.push(`Detected payment-related keywords (${payMatches})`);
    score += Math.min(40, 10 * payMatches); // each adds weight but cap
  }

  // 5) scammy phrases (earn/daily/no interview)
  const scamPhraseMatches = countMatches(lowered, scamPhrases);
  features.scamPhraseCount = scamPhraseMatches;
  if(scamPhraseMatches > 0) {
    reasons.push(`Detected too-good-to-be-true phrases (${scamPhraseMatches})`);
    score += Math.min(30, 8 * scamPhraseMatches);
  }

  // 6) URL / hostname checks (if value contains a URL or appears like one)
  let urlHost = null;
  try {
    // try to find a URL in text
    const urlMatch = lowered.match(/https?:\/\/[^\s)]+/i);
    const maybe = urlMatch ? urlMatch[0] : (lowered.match(/\b[\w.-]+\.(com|in|xyz|info|org|net|club|site|online)\b/i) || [null])[0];
    if(maybe){
      const u = new URL( maybe.startsWith('http') ? maybe : 'https://' + maybe );
      urlHost = u.hostname;
      features.hostname = urlHost;
      const parts = urlHost.split('.');
      const tld = parts[parts.length-1];
      if(suspiciousTLDs.has(tld)) {
        reasons.push(`Suspicious domain TLD .${tld}`);
        score += 18;
        features.suspiciousTLD = true;
      }
      if((urlHost.match(/-/g)||[]).length > 1){
        reasons.push('Hostname contains multiple hyphens — common in spoof domains');
        score += 6;
      }
      const ent = hostnameEntropy(urlHost);
      features.hostEntropy = ent;
      if(ent > 3.2) {
        reasons.push('Hostname looks randomized (high entropy) — suspicious');
        score += 10;
      }
      // https check
      if(maybe && !maybe.startsWith('https://')) {
        // if it's http or no protocol in text, small penalty
        if(maybe.startsWith('http://')) {
          reasons.push('Using http (not https) — data not secured by TLS');
          score += 4;
        }
      }
    }
  } catch(e){
    // ignore URL parsing errors
  }

  // 7) suspicious phrasing: "send screenshot", "send money", "you are selected, pay"
  const susPhrases = ['send screenshot','send payment','send money','you are selected','selected for internship','selected for job','pay to confirm','pay to process','pay now'];
  const susCount = countMatches(lowered, susPhrases);
  features.susPhraseCount = susCount;
  if(susCount > 0) {
    reasons.push(`Phrases indicating payment/confirmation flow (${susCount})`);
    score += Math.min(30, 12 * susCount);
  }

  // 8) short message, many exclamation or ALL CAPS
  const exclam = (lowered.match(/!/g)||[]).length;
  const capsRatio = (() => {
    const letters = (value.match(/[A-Z]/g)||[]).length + (value.match(/[a-z]/g)||[]).length;
    if(letters === 0) return 0;
    return (value.match(/[A-Z]/g)||[]).length / letters;
  })();
  features.exclamCount = exclam;
  features.capsRatio = Math.round(capsRatio * 100) / 100;
  if(exclam > 2) { score += 3; reasons.push('Excessive exclamation marks'); }
  if(capsRatio > 0.6) { score += 4; reasons.push('Message uses unusual ALL CAPS'); }

  // 9) contradiction: says "no fees required" AND contains payment keywords -> suspicious
  if(lowered.includes('no fees') || lowered.includes('no fee') || lowered.includes('no payment required')){
    if(payMatches > 0) {
      reasons.push('Message claims no fees required but also mentions payment-related words — contradictory');
      score += 12;
    }
  }

  // 10) final aggregation: normalize and clamp
  score = Math.min(100, Math.round(score));

  // If nothing suspicious found, add green reason
  if(score === 0) reasons.push('No immediate red flags found');

  const level = score >= 60 ? 'red' : score >= 30 ? 'yellow' : 'green';

  return {
    score,
    level,
    reasons,
    features
  };
}

module.exports = { analyze };
