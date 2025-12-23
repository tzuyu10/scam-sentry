// constants.ts
import type { CategoryWeights } from '../types/types';

export const CATEGORY_WEIGHTS: CategoryWeights = {
  URGENCY: 1.0,
  FINANCIAL: 1.2,
  PHISHING: 1.5,
  IMPERSONATION: 1.3,
  URL: 1.4,
};

export const SAMPLE_SCAMS = [
  "URGENT! Your GCash account has been suspended. Verify your account now by clicking bit.ly/gcash123 and enter your OTP immediately.",
  "Congratulations! You won PHP 500,000 cash prize! Claim your reward now. Contact our official customer service.",
  "From BPI Security Team: Unusual activity detected. Please i-verify your account agad by sending your OTP.",
  "FREE LOAN offer! Instant approval, no collateral needed. Kumita ng malaki with our investment program."
];