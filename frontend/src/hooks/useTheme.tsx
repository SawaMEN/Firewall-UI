import {
  createContext,
  useCallback,
  useContext,
  useLayoutEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import { theme as antdTheme, type ThemeConfig } from 'antd';
import { usePageVisibility } from './usePageVisibility';

export type ThemeMode = 'light' | 'dark' | 'cyberpunk';
const STORAGE_THEME = 'firewall-theme';

function readTheme(): ThemeMode {
  try {
    const saved =
      localStorage.getItem(STORAGE_THEME);
    if (saved === 'light' || saved === 'colorful') return 'light';
    if (saved === 'cyberpunk') return 'cyberpunk';
    if (saved === 'dark') return 'dark';
  } catch {
    /* Private browser storage can be unavailable. */
  }
  return 'cyberpunk';
}

const palettes = {
  light: {
    background: '#f5f6fa',
    surface: '#ffffff',
    elevated: '#ffffff',
    text: '#192231',
    secondary: '#677386',
    border: '#dce2ec',
    primary: '#2563eb',
  },
  dark: {
    background: '#10141c',
    surface: '#181e29',
    elevated: '#222b39',
    text: '#edf2fb',
    secondary: '#a2afc2',
    border: '#303c4e',
    primary: '#7ba5ff',
  },
  cyberpunk: {
    background: '#090b12',
    surface: '#101522',
    elevated: '#192236',
    text: '#eafcff',
    secondary: '#9bb4cc',
    border: '#284358',
    primary: '#37d8e9',
  },
};

function buildTheme(mode: ThemeMode): ThemeConfig {
  const colors = palettes[mode];
  return {
    hashed: false,
    cssVar: { key: 'firewall' },
    algorithm:
      mode === 'light' ? antdTheme.defaultAlgorithm : antdTheme.darkAlgorithm,
    token: {
      motion: false,
      colorPrimary: colors.primary,
      colorLink: colors.primary,
      colorBgBase: colors.background,
      colorBgLayout: colors.background,
      colorBgContainer: colors.surface,
      colorBgElevated: colors.elevated,
      colorText: colors.text,
      colorTextSecondary: colors.secondary,
      colorTextDescription: colors.secondary,
      colorTextTertiary: colors.secondary,
      colorSuccessText: mode === 'light' ? '#16804d' : '#76d9a8',
      colorErrorText: mode === 'light' ? '#c83749' : '#ff929f',
      colorTextPlaceholder: colors.secondary,
      colorBorder: colors.border,
      colorBorderSecondary: colors.border,
      borderRadius: 10,
      borderRadiusLG: 16,
      controlHeight: 40,
      fontFamily: 'system-ui, -apple-system, "Segoe UI", sans-serif',
    },
    components: {
      Layout: {
        bodyBg: colors.background,
        siderBg: colors.surface,
        triggerBg: colors.elevated,
        triggerColor: colors.text,
      },
      Statistic: { contentFontSize: 22, titleFontSize: 13 },
    },
  };
}

function applyTheme(mode: ThemeMode) {
  document.documentElement.dataset.theme = mode;
  document.documentElement.style.colorScheme =
    mode === 'light' ? 'light' : 'dark';
}
const initialTheme = readTheme();
applyTheme(initialTheme);

type ThemeContextValue = {
  mode: ThemeMode;
  setThemeMode: (mode: ThemeMode) => void;
  antdThemeConfig: ThemeConfig;
};
const ThemeContext = createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const visible = usePageVisibility();
  useLayoutEffect(() => {
    document.documentElement.dataset.pageVisible = String(visible);
  }, [visible]);
  const [mode, setMode] = useState<ThemeMode>(initialTheme);
  useLayoutEffect(() => {
    applyTheme(mode);
    try {
      localStorage.setItem(STORAGE_THEME, mode);
      for (const key of [
        'dark-mode',
        'isUltraDarkThemeEnabled',
      ])
        localStorage.removeItem(key);
    } catch {
      /* Theme changes still work without persistent storage. */
    }
  }, [mode]);
  const setThemeMode = useCallback((next: ThemeMode) => setMode(next), []);
  const antdThemeConfig = useMemo(() => buildTheme(mode), [mode]);
  const value = useMemo(
    () => ({ mode, setThemeMode, antdThemeConfig }),
    [mode, setThemeMode, antdThemeConfig],
  );
  return (
    <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
  );
}
export function useTheme() {
  const value = useContext(ThemeContext);
  if (!value) throw new Error('ThemeProvider is required');
  return value;
}
