import type {
	ExpressiveCodeConfig,
	LicenseConfig,
	NavBarConfig,
	ProfileConfig,
	SiteConfig,
} from "./types/config";
import { LinkPreset } from "./types/config";

export const siteConfig: SiteConfig = {
	title: "Delorian's Blog",
	subtitle: "Delorian's Blog",
	lang: "en", // Language code, e.g. 'en', 'zh_CN', 'ja', etc.
	themeColor: {
		hue: 305, // Default hue for the theme color, from 0 to 360. e.g. red: 0, teal: 200, cyan: 250, pink: 345
		fixed: false, // Hide the theme color picker for visitors
	},
	banner: {
		enable: true,
		src: "https://github.com/HyDE-Project/hyde-themes/blob/Catppuccin-Mocha/Configs/.config/hyde/themes/Catppuccin%20Mocha/wallpapers/cat_leaves.png?raw=true", // Relative to the /src directory. Relative to the /public directory if it starts with '/'
		position: "center", // Equivalent to object-position, only supports 'top', 'center', 'bottom'. 'center' by default
		credit: {
			enable: true, // Display the credit text of the banner image
			text: "easter egg found!", // Credit text to be displayed
			url: "https://nobodyhere.com/justme/me.here", // (Optional) URL link to the original artwork or artist's page
		},
	},
	toc: {
		enable: true, // Display the table of contents on the right side of the post
		depth: 2, // Maximum heading depth to show in the table, from 1 to 3
	},
	favicon: [
		// Leave this array empty to use the default favicon
		 {
		   src: 'https://i.pinimg.com/1200x/7d/6d/cd/7d6dcd3b4cd13635e6c58017b29d603b.jpg',    // Path of the favicon, relative to the /public directory
		//   theme: 'light',              // (Optional) Either 'light' or 'dark', set only if you have different favicons for light and dark mode
		   sizes: '32x32',              // (Optional) Size of the favicon, set only if you have favicons of different sizes
		 }
	],
};

export const navBarConfig: NavBarConfig = {
	links: [
		LinkPreset.Home,
		LinkPreset.Archive,
		LinkPreset.About,
		{
			name: "HackTheBox",
			url: "https://app.hackthebox.com/profile/2378119", // Internal links should not include the base path, as it is automatically added
			external: true, // Show an external link icon and will open in a new tab
		},
	],
};

export const profileConfig: ProfileConfig = {
	avatar: "https://i.pinimg.com/1200x/7d/6d/cd/7d6dcd3b4cd13635e6c58017b29d603b.jpg", // Relative to the /src directory. Relative to the /public directory if it starts with '/'
	name: "Delorian",
	bio: "Pentesting & Red Teaming - eCPPT | eJPT | CRTP...",
	links: [
		{
			name: "Discord",
			icon: "fa6-brands:discord", // Visit https://icones.js.org/ for icon codes
			// You will need to install the corresponding icon set if it's not already included
			// `pnpm add @iconify-json/<icon-set-name>`
			url: "https://discord.com/users/1371508453067198619",
		},
		{
			name: "HackTheBox",
			icon: "mdi:cube-outline",
			url: "https://app.hackthebox.com/profile/2378119",
		},
		{
			name: "GitHub",
			icon: "fa6-brands:github",
			url: "https://github.com/DelorianCS",
		},
{
			name: "Monkeytype",
			icon: "mdi:keyboard",
			url: "https://monkeytype.com/profile/DelorianCS",
		},
	],
};

export const licenseConfig: LicenseConfig = {
	enable: true,
	name: "CC BY-NC-SA 4.0",
	url: "https://creativecommons.org/licenses/by-nc-sa/4.0/",
};

export const expressiveCodeConfig: ExpressiveCodeConfig = {
	// Note: Some styles (such as background color) are being overridden, see the astro.config.mjs file.
	// Please select a dark theme, as this blog theme currently only supports dark background color
	theme: "github-dark",
};
