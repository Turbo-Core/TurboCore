export default {
  logo: <h1>TurboCore Docs</h1>,
  project: {
    link: 'https://blog.samiyousef.ca',
  },
  useNextSeoProps() {
	  return {
	    titleTemplate: '%s - TurboCore',
	    description: 'API documentation for TurboCore'
	  }
  },
  darkMode: true,
  primaryHue: 212,
  footer: {
    text: <span>
      {new Date().getFullYear()} © TurboCore.
    </span>,
  }
  // https://nextra.site/docs/docs-theme/theme-configuration
}
