import amplitude from 'amplitude-js';

const AMPLITUDE_API_KEY = '70952581a5fe3101de0eaadf90af23ab';
const amplitudeInstance = amplitude.getInstance();
amplitudeInstance.init(AMPLITUDE_API_KEY);

export const trackEvent = (eventName: string, properties: any = {}) => {
    amplitudeInstance.logEvent(eventName, properties);
};
