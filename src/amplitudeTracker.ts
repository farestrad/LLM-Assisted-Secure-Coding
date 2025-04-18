// Remove dotenv — no need for it at runtime
// import * as dotenv from 'dotenv';
// dotenv.config(); <-- not needed

import * as amplitude from '@amplitude/node';

const AMPLITUDE_API_KEY = process.env.AMPLITUDE_API_KEY || '';

if (!AMPLITUDE_API_KEY) {
    console.error('Amplitude API Key not found — make sure it’s injected at build time!');
}

const client = amplitude.init(AMPLITUDE_API_KEY);

export const trackEvent = (eventName: string, properties: any = {}) => {
    client.logEvent({
        event_type: eventName,
        event_properties: properties,
    });
};
