<?php

namespace NimblePHP\Authorization;

/**
 * Language translation helper
 * 
 * @package NimblePHP\Authorization
 */
class Lang
{
    /**
     * Loaded translations
     * @var array
     */
    private static array $translations = [];

    /**
     * Current language
     * @var string
     */
    private static string $currentLanguage = 'en';

    /**
     * Set current language
     * 
     * @param string $language Language code (en, pl, etc.)
     * @return void
     */
    public static function setLanguage(string $language): void
    {
        self::$currentLanguage = $language;
        self::loadTranslations($language);
    }

    /**
     * Get current language
     * 
     * @return string
     */
    public static function getLanguage(): string
    {
        return self::$currentLanguage;
    }

    /**
     * Load translations for language
     * 
     * @param string $language Language code
     * @return void
     */
    private static function loadTranslations(string $language): void
    {
        $file = __DIR__ . '/Lang/' . $language . '.php';

        if (file_exists($file)) {
            self::$translations[$language] = require $file;
        } else {
            // Fallback to English if language file not found
            if ($language !== 'en') {
                self::loadTranslations('en');
            }
        }
    }

    /**
     * Get translation by key
     * 
     * @param string $key Translation key (e.g., 'validation.username_empty')
     * @param array $replace Replacement values for placeholders
     * @return string Translated text
     */
    public static function get(string $key, array $replace = []): string
    {
        // Load translations if not loaded yet
        if (!isset(self::$translations[self::$currentLanguage])) {
            self::loadTranslations(self::$currentLanguage);
        }

        // Get translation
        $keys = explode('.', $key);
        $translation = self::$translations[self::$currentLanguage] ?? [];

        foreach ($keys as $k) {
            if (isset($translation[$k])) {
                $translation = $translation[$k];
            } else {
                // Return key if translation not found
                return $key;
            }
        }

        // Replace placeholders
        if (!empty($replace)) {
            foreach ($replace as $placeholder => $value) {
                $translation = str_replace('{' . $placeholder . '}', $value, $translation);
            }
        }

        return $translation;
    }

    /**
     * Alias for get() method
     * 
     * @param string $key Translation key
     * @param array $replace Replacement values
     * @return string Translated text
     */
    public static function trans(string $key, array $replace = []): string
    {
        return self::get($key, $replace);
    }
}
