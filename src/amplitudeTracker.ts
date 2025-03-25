import amplitude from 'amplitude-js';
import * as dotenv from 'dotenv';

dotenv.config();

const AMPLITUDE_API_KEY = process.env.AMPLITUDE_API_KEY || '';

if (!AMPLITUDE_API_KEY) {
    console.error('Amplitude API Key not found in .env file');
}

<<<<<<< HEAD
const AMPLITUDE_API_KEY = '70952581a5fe3101de0eaadf90af23ab'; //.Env hidden files??
=======
>>>>>>> 0fe8a09af6d4fe1139b256c7aa82a4c09f77a8c0
const amplitudeInstance = amplitude.getInstance();
amplitudeInstance.init(AMPLITUDE_API_KEY);

export const trackEvent = (eventName: string, properties: any = {}) => {
    amplitudeInstance.logEvent(eventName, properties);
};



