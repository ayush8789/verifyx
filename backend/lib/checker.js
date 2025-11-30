// backend/lib/checker.js
// Stronger rule-based detector for VerifyX (higher sensitivity)

const suspiciousTLDs = new Set(['xyz','info','top','bit','club','loan','online','site']);
const freeEmailPatterns = /\b(gmail|yahoo|hotmail|outlook|rediff|yandex|protonmail)\b/i;

const paymentKeywords = [
  'processing fee','registration fee','security deposit','pay before','pay to',
  'refund','transfer','upi','bank account','account number','pay via','paytm',
  'gpay','phonepe','deposit','send money','send ₹','send rs','send rs.',
  'send inr','pay now','pay ₹','pay rs','join fee'
];

const scamPhrases = [
  'work from home','earn ₹','earn rs','earn per day','no interview','join immediately',
  'urgent hiring','limited seats','only','guaranteed','100% placement','get paid daily',
  'no experience required','apply now','contact hr'
];

const phoneRegex = /(?:\+91|91)?[\s\-]?(?:[6-9]\d{9}|\d{3}[\-]\d{3}[\-]\d{4})/g;
const upiRegex = /\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b/g; // basic UPI id like name@okaxis
const emailRegex = /[\w.+-]+@([\w-]+\.)+[\w-]{2,}/g;

// hostname entropy helper
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
  return Math.min(6, ent); // wider scale
}

function countMatches(text, list) {
  if(!text) return 0;
  const lower = text.toLowerCase();
  let count = 0;
  for(const k of list) if(lower.includes(k)) count++;
  return count;
}

function analyze(type='text', value=''){
  const reasons = [];
  const lowered = (value || '').toString().trim();
  let score = 0;
  const features = {};

  // emails
  const emails = (lowered.match(emailRegex) || []);
  features.emailCount = emails.length;
  if(emails.length > 0) {
    const freeEmails = emails.filter(e => freeEmailPatterns.test(e));
    if(freeEmails.length > 0) {
      reasons.push(`Using free email provider (${freeEmails.slice(0,2).join(', ')})`);
      score += 30;
      features.freeEmailCount = freeEmails.length;
    } else {
      // corporate-looking emails slightly reduce suspicion
      score += 0;
    }
  }

  // phone numbers
  const phones = (lowered.match(phoneRegex) || []);
  features.phoneCount = phones.length;
  if(phones.length > 0) {
    reasons.push(`Phone/WhatsApp number detected (${phones[0]})`);
    score += 18;
  }

  // UPI IDs
  const upis = (lowered.match(upiRegex) || []);
  features.upiCount = upis.length;
  if(upis.length > 0) {
    reasons.push(`UPI/payment id detected (${upis[0]})`);
    score += 45;
  }

  // payment keywords (stronger weight)
  const payMatches = countMatches(lowered, paymentKeywords);
  features.paymentKeywordCount = payMatches;
  if(payMatches > 0) {
    reasons.push(`Detected payment-related keywords (${payMatches})`);
    score += Math.min(60, 18 * payMatches); // high impact
  }

  // scammy phrases
  const scamPhraseMatches = countMatches(lowered, scamPhrases);
  features.scamPhraseCount = scamPhraseMatches;
  if(scamPhraseMatches > 0) {
    reasons.push(`Detected suspicious phrases (${scamPhraseMatches})`);
    score += Math.min(36, 12 * scamPhraseMatches);
  }

  // URL / hostname checks
  let urlHost = null;
  try {
    const urlMatch = lowered.match(/https?:\/\/[^\s)]+/i);
    const maybe = urlMatch ? urlMatch[0] : (lowered.match(/\b[\w.-]+\.(com|in|xyz|info|org|net|club|site|online)\b/i) || [null])[0];
    if(maybe){
      const u = new URL( maybe.startsWith('http') ? maybe : 'https://' + maybe );
      urlHost = u.hostname;
      features.hostname = urlHost;
      const parts = urlHost.split('.');
      const tld = parts[parts.length-1];
      if(suspiciousTLDs.has(tld)) {
        reasons.push(`Suspicious TLD .${tld}`);
        score += 22;
        features.suspiciousTLD = true;
      }
      if((urlHost.match(/-/g)||[]).length > 1){
        reasons.push('Hostname contains multiple hyphens');
        score += 8;
      }
      const ent = hostnameEntropy(urlHost);
      features.hostEntropy = ent;
      if(ent > 3.5) {
        reasons.push('Hostname looks randomized (high entropy)');
        score += 14;
      }
      if(maybe.startsWith('http://')) {
        reasons.push('Using http (not https)');
        score += 6;
      }
    }
  } catch(e){ /* ignore */ }

  // suspicious phrases that require action
  const susPhrases = ['send screenshot','send payment','send money','you are selected','selected for internship','selected for job','pay to confirm','pay to process','pay now'];
  const susCount = countMatches(lowered, susPhrases);
  features.susPhraseCount = susCount;
  if(susCount > 0) {
    reasons.push(`Action/payment flow phrases (${susCount})`);
    score += Math.min(45, 15 * susCount);
  }

  // punctuation / caps
  const exclam = (lowered.match(/!/g)||[]).length;
  const letters = (value.match(/[A-Z]/g)||[]).length + (value.match(/[a-z]/g)||[]).length;
  const capsRatio = letters === 0 ? 0 : (value.match(/[A-Z]/g)||[]).length / letters;
  features.exclamCount = exclam;
  features.capsRatio = Math.round(capsRatio * 100) / 100;
  if(exclam > 2) { score += 4; reasons.push('Excessive exclamation marks'); }
  if(capsRatio > 0.6) { score += 6; reasons.push('Unusual ALL CAPS usage'); }

  // contradiction: "no fees" + pay words
  if((lowered.includes('no fees') || lowered.includes('no fee') || lowered.includes('no payment required')) && payMatches > 0) {
    reasons.push('Claims no fees but mentions payment — contradictory');
    score += 14;
  }

  // final normalization
  score = Math.min(100, Math.round(score));

  if(score === 0) reasons.push('No immediate red flags found');

  const level = score >= 60 ? 'red' : score >= 30 ? 'yellow' : 'green';

  return { score, level, reasons, features };
}

module.exports = { analyze };
