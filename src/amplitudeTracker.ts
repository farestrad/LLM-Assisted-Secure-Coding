import amplitude from 'amplitude-js';
import * as dotenv from 'dotenv';

dotenv.config();

const AMPLITUDE_API_KEY = process.env.AMPLITUDE_API_KEY || '';

if (!AMPLITUDE_API_KEY) {
    console.error('Amplitude API Key not found in .env file');
}

const amplitudeInstance = amplitude.getInstance();
amplitudeInstance.init(AMPLITUDE_API_KEY);

export const trackEvent = (eventName: string, properties: any = {}) => {
    amplitudeInstance.logEvent(eventName, properties);
};



