import { createContext, useCallback, useContext, useLayoutEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { theme as antdTheme } from 'antd';
import type { ThemeConfig } from 'antd';

const STORAGE_DARK = 'dark-mode';
const STORAGE_ULTRA = 'isUltraDarkThemeEnabled';
const STORAGE_THEME = 'xui-theme';
const STORAGE_LOW_POWER = 'xui-low-power';

export type ThemeMode = 'light' | 'dark' | 'ultra-dark' | 'colorful' | 'blue-gray' | 'cyberpunk';

function readBool(key: string, fallback: boolean): boolean {
  const raw = localStorage.getItem(key);
  if (raw === null) return fallback;
  return raw === 'true';
}

function readLowPower(): boolean {
  return readBool(STORAGE_LOW_POWER, false);
}

function readThemeMode(): ThemeMode {
  const saved = localStorage.getItem(STORAGE_THEME);
  if (
    saved === 'light' ||
    saved === 'dark' ||
    saved === 'ultra-dark' ||
    saved === 'colorful' ||
    saved === 'blue-gray' ||
    saved === 'cyberpunk'
  )
    return saved;

  // Cyberpunk is the default visual identity when no explicit theme was saved.
  // Legacy dark-mode flags are mirrored after the provider mounts, so they do
  // not override the new default on first load after the theme upgrade.
  return 'cyberpunk';
}

function applyDom(mode: ThemeMode, lowPower: boolean) {
  const isDark =
    mode === 'dark' || mode === 'ultra-dark' || mode === 'blue-gray' || mode === 'cyberpunk';
  document.body.classList.remove(
    'dark',
    'light',
    'theme-light',
    'theme-ultra-dark',
    'theme-colorful',
    'theme-blue-gray',
    'theme-cyberpunk',
  );
  document.body.classList.add(isDark ? 'dark' : 'light', 'theme-' + mode);
  document.documentElement.style.colorScheme = isDark ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', mode);
  document.documentElement.setAttribute('data-low-power', String(lowPower));
  const msg = document.getElementById('message');
  if (msg) {
    msg.classList.remove('dark', 'light');
    msg.classList.add(isDark ? 'dark' : 'light');
  }
}

const initialMode = readThemeMode();
const initialLowPower = readLowPower();
applyDom(initialLowPower ? 'dark' : initialMode, initialLowPower);

const ULTRA_DARK_TOKENS = {
  colorBgBase: '#000000',
  colorBgLayout: '#000000',
  colorBgContainer: '#08090c',
  colorBgElevated: '#111318',
};
const ULTRA_DARK_LAYOUT_TOKENS = {
  bodyBg: '#000000',
  headerBg: '#050507',
  headerColor: '#ffffff',
  footerBg: '#000000',
  siderBg: '#050507',
  triggerBg: '#1a1a1e',
  triggerColor: '#ffffff',
};
const ULTRA_DARK_MENU_TOKENS = {
  darkItemBg: '#050507',
  darkSubMenuItemBg: '#0a0b0e',
  darkPopupBg: '#111318',
};
const LIGHT_TOKENS = {
  colorBgBase: '#f5f5f7',
  colorBgLayout: '#f5f5f7',
  colorBgContainer: '#ffffff',
  colorBgElevated: '#fbfbfd',
  colorText: '#1d1d1f',
  colorTextSecondary: '#6e6e73',
  colorBorder: '#d2d2d7',
  colorBorderSecondary: '#e5e5ea',
};
const DARK_TOKENS = {
  colorBgBase: '#141218',
  colorBgLayout: '#141218',
  colorBgContainer: '#211f26',
  colorBgElevated: '#2b2930',
  colorText: '#e6e0e9',
  colorTextSecondary: '#cac4d0',
  colorBorder: '#938f99',
  colorBorderSecondary: '#49454f',
};
const BLUE_GRAY_TOKENS = {
  colorBgBase: '#101722',
  colorBgLayout: '#101722',
  colorBgContainer: '#182333',
  colorBgElevated: '#223147',
};
const COLORFUL_TOKENS = {
  colorBgBase: '#fbf8ff',
  colorBgLayout: '#f8f5ff',
  colorBgContainer: '#fffaff',
  colorBgElevated: '#f1ecff',
};
const DARK_LAYOUT_TOKENS = {
  bodyBg: '#141218',
  headerBg: '#1d1b20',
  headerColor: '#ffffff',
  footerBg: '#141218',
  siderBg: '#1d1b20',
  triggerBg: '#2b2930',
  triggerColor: '#ffffff',
};
const BLUE_GRAY_LAYOUT_TOKENS = {
  bodyBg: '#101722',
  headerBg: '#0c131d',
  headerColor: '#f2f6fb',
  footerBg: '#101722',
  siderBg: '#0c131d',
  triggerBg: '#182333',
  triggerColor: '#f2f6fb',
};
const DARK_MENU_TOKENS = {
  darkItemBg: '#15161a',
  darkSubMenuItemBg: '#1a1b1f',
  darkPopupBg: '#23252b',
};
const BLUE_GRAY_MENU_TOKENS = {
  darkItemBg: '#0c131d',
  darkSubMenuItemBg: '#101722',
  darkPopupBg: '#182333',
};
const DARK_CARD_TOKENS = {
  colorBorderSecondary: 'rgba(255, 255, 255, 0.06)',
};
const BLUE_GRAY_CARD_TOKENS = {
  colorBorderSecondary: 'rgba(190, 210, 235, 0.14)',
};
const STATISTIC_TOKENS = {
  contentFontSize: 17,
  titleFontSize: 11,
};
const LIGHT_CONTRAST_TOKENS = {
  colorTextDescription: 'rgba(29, 29, 31, 0.68)',
  colorTextTertiary: 'rgba(29, 29, 31, 0.60)',
  colorTextPlaceholder: '#6e6e73',
  colorError: '#d70015',
  colorErrorText: '#c41d3a',
  colorSuccessText: '#1f7a1f',
};
const CYBER_TOKENS = {
  colorBgBase: '#07070b',
  colorBgLayout: '#09090f',
  colorBgContainer: '#0e0f17',
  colorBgElevated: '#151722',
  colorText: '#f5f7ff',
  colorTextSecondary: '#a8b0c8',
  colorBorder: '#31364e',
  colorBorderSecondary: '#23283a',
};
const MATERIAL_TOKENS = {
  colorPrimary: '#0071e3',
  colorPrimaryHover: '#0077ed',
  colorPrimaryActive: '#0068d6',
  colorLink: '#0071e3',
  borderRadius: 12,
  borderRadiusLG: 18,
  controlHeight: 40,
};
const THEME_FONTS = {
  light: '-apple-system, BlinkMacSystemFont, "SF Pro Display", "Helvetica Neue", Arial, sans-serif',
  dark: 'Inter, "Segoe UI", system-ui, sans-serif',
  'ultra-dark': '"IBM Plex Sans", "Segoe UI", Arial, sans-serif',
  colorful: '"Avenir Next", Avenir, "Trebuchet MS", sans-serif',
  'blue-gray': '"Source Sans 3", "Segoe UI", Arial, sans-serif',
  cyberpunk: '"Exo 2", "Segoe UI", system-ui, sans-serif',
} as const;
const LIGHT_THEME_TOKENS = {
  colorPrimary: '#0071e3',
  colorPrimaryHover: '#0077ed',
  colorPrimaryActive: '#0068d6',
  colorLink: '#0071e3',
};
const CYBER_LAYOUT_TOKENS = {
  bodyBg: '#09090f',
  headerBg: '#0a0b11',
  headerColor: '#f5f7ff',
  footerBg: '#09090f',
  siderBg: '#080910',
  triggerBg: '#171a27',
  triggerColor: '#f5f7ff',
};
const CYBER_MENU_TOKENS = {
  darkItemBg: '#080910',
  darkSubMenuItemBg: '#0d0f18',
  darkPopupBg: '#121522',
};
const CYBER_CARD_TOKENS = {
  colorBorderSecondary: 'rgba(87, 245, 255, 0.16)',
};

const SHARED_STYLE_CONFIG = {
  hashed: false,
  cssVar: { key: 'xui' },
} as const;

export function buildAntdThemeConfig(mode: ThemeMode): ThemeConfig {
  if (mode === 'ultra-dark') {
    return {
      ...SHARED_STYLE_CONFIG,
      algorithm: antdTheme.darkAlgorithm,
      token: {
        ...ULTRA_DARK_TOKENS,
        ...MATERIAL_TOKENS,
        fontFamily: THEME_FONTS['ultra-dark'],
      },
      components: {
        Layout: ULTRA_DARK_LAYOUT_TOKENS,
        Menu: ULTRA_DARK_MENU_TOKENS,
        Statistic: STATISTIC_TOKENS,
      },
    };
  }
  if (mode === 'colorful') {
    return {
      ...SHARED_STYLE_CONFIG,
      algorithm: antdTheme.defaultAlgorithm,
      token: {
        ...COLORFUL_TOKENS,
        ...MATERIAL_TOKENS,
        colorPrimary: '#7c3aed',
        colorPrimaryHover: '#8b5cf6',
        colorPrimaryActive: '#6d28d9',
        colorLink: '#7c3aed',
        fontFamily: THEME_FONTS.colorful,
      },
      components: { Statistic: STATISTIC_TOKENS },
    };
  }
  if (mode === 'blue-gray') {
    return {
      ...SHARED_STYLE_CONFIG,
      algorithm: antdTheme.darkAlgorithm,
      token: {
        ...BLUE_GRAY_TOKENS,
        ...MATERIAL_TOKENS,
        colorPrimary: '#8ab4f8',
        colorPrimaryHover: '#a8c7fa',
        colorPrimaryActive: '#6ea0e8',
        colorLink: '#8ab4f8',
        fontFamily: THEME_FONTS['blue-gray'],
      },
      components: {
        Layout: BLUE_GRAY_LAYOUT_TOKENS,
        Menu: BLUE_GRAY_MENU_TOKENS,
        Card: BLUE_GRAY_CARD_TOKENS,
        Statistic: STATISTIC_TOKENS,
      },
    };
  }
  if (mode === 'light') {
    return {
      ...SHARED_STYLE_CONFIG,
      algorithm: antdTheme.defaultAlgorithm,
      token: {
        ...LIGHT_TOKENS,
        ...LIGHT_CONTRAST_TOKENS,
        ...MATERIAL_TOKENS,
        ...LIGHT_THEME_TOKENS,
        fontFamily: THEME_FONTS.light,
      },
      components: { Statistic: STATISTIC_TOKENS },
    };
  }
  if (mode === 'cyberpunk') {
    return {
      ...SHARED_STYLE_CONFIG,
      algorithm: antdTheme.darkAlgorithm,
      token: {
        ...CYBER_TOKENS,
        ...MATERIAL_TOKENS,
        colorPrimary: '#d4a017',
        colorPrimaryHover: '#e0b52a',
        colorPrimaryActive: '#b8870f',
        colorLink: '#e0b52a',
        colorSuccess: '#b6c35a',
        colorWarning: '#e7b52a',
        colorError: '#e35b3f',
        fontFamily: THEME_FONTS.cyberpunk,
      },
      components: {
        Layout: CYBER_LAYOUT_TOKENS,
        Menu: CYBER_MENU_TOKENS,
        Card: CYBER_CARD_TOKENS,
        Statistic: STATISTIC_TOKENS,
      },
    };
  }
  return {
    ...SHARED_STYLE_CONFIG,
    algorithm: antdTheme.darkAlgorithm,
    token: {
      ...DARK_TOKENS,
      ...MATERIAL_TOKENS,
      fontFamily: THEME_FONTS.dark,
    },
    components: {
      Layout: DARK_LAYOUT_TOKENS,
      Menu: DARK_MENU_TOKENS,
      Card: DARK_CARD_TOKENS,
      Statistic: STATISTIC_TOKENS,
    },
  };
}

export function pauseAnimationsUntilLeave(elementId: string): void {
  document.documentElement.setAttribute('data-theme-animations', 'off');
  const el = document.getElementById(elementId);
  if (!el) return;
  const restore = () => {
    document.documentElement.removeAttribute('data-theme-animations');
    el.removeEventListener('mouseleave', restore);
    el.removeEventListener('touchend', restore);
  };
  el.addEventListener('mouseleave', restore);
  el.addEventListener('touchend', restore);
}

interface ThemeContextValue {
  mode: ThemeMode;
  isDark: boolean;
  isUltra: boolean;
  toggleTheme: () => void;
  toggleUltra: () => void;
  setThemeMode: (mode: ThemeMode) => void;
  antdThemeConfig: ThemeConfig;
  lowPower: boolean;
  toggleLowPower: () => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [mode, setMode] = useState<ThemeMode>(initialMode);
  const [lowPower, setLowPower] = useState<boolean>(() => readLowPower());
  const activeMode: ThemeMode = lowPower ? 'dark' : mode;
  const isDark =
    activeMode === 'dark' ||
    activeMode === 'ultra-dark' ||
    activeMode === 'blue-gray' ||
    activeMode === 'cyberpunk';
  const isUltra = activeMode === 'ultra-dark';

  useLayoutEffect(() => {
    applyDom(activeMode, lowPower);
    localStorage.setItem(STORAGE_THEME, mode);
    localStorage.setItem(STORAGE_LOW_POWER, String(lowPower));
    localStorage.setItem(STORAGE_DARK, String(isDark));
    localStorage.setItem(STORAGE_ULTRA, String(isUltra));
  }, [activeMode, mode, isDark, isUltra, lowPower]);

  const toggleTheme = useCallback(
    () =>
      setMode((v) => (v === 'light' ? 'dark' : v === 'dark' || v === 'ultra-dark' ? 'light' : v)),
    [],
  );
  const toggleUltra = useCallback(
    () => setMode((v) => (v === 'dark' ? 'ultra-dark' : v === 'ultra-dark' ? 'dark' : v)),
    [],
  );
  const setThemeMode = useCallback((next: ThemeMode) => setMode(next), []);
  const toggleLowPower = useCallback(() => setLowPower((enabled) => !enabled), []);

  const antdThemeConfig = useMemo(() => buildAntdThemeConfig(activeMode), [activeMode]);

  const value = useMemo<ThemeContextValue>(
    () => ({
      mode,
      isDark,
      isUltra,
      toggleTheme,
      toggleUltra,
      setThemeMode,
      antdThemeConfig,
      lowPower,
      toggleLowPower,
    }),
    [
      mode,
      isDark,
      isUltra,
      toggleTheme,
      toggleUltra,
      setThemeMode,
      antdThemeConfig,
      lowPower,
      toggleLowPower,
    ],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error('useTheme must be used inside <ThemeProvider>');
  return ctx;
}
