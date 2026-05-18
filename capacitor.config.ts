import type { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.jiprop.titlemonitor',
  appName: 'JIPROP',
  webDir: 'www',
  server: {
    androidScheme: 'https',
    allowNavigation: []
  },
  ios: {
    backgroundColor: '#f5f5f7',
    contentInset: 'always',
    preferredContentMode: 'mobile',
    limitsNavigationsToAppBoundDomains: true,
    scrollEnabled: true
  },
  android: {
    backgroundColor: '#f5f5f7',
    allowMixedContent: false
  },
  plugins: {
    SplashScreen: {
      launchShowDuration: 1500,
      backgroundColor: '#f5f5f7',
      androidSplashResourceName: 'splash',
      androidScaleType: 'CENTER_CROP',
      showSpinner: false
    }
  }
};

export default config;
