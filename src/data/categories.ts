import {
    Globe, Terminal, Monitor, Smartphone,
    Wrench
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

export interface Category {
    label: string;
    icon: LucideIcon;
    description?: string;
}

export const CATEGORIES: Record<string, Category> = {
    WEB: {
        label: 'Web',
        icon: Globe,
        description: 'Web application security tools'
    },
    WINDOWS: {
        label: 'Windows',
        icon: Monitor,
        description: 'Windows post-exploitation'
    },
    LINUX: {
        label: 'Linux',
        icon: Terminal,
        description: 'Linux post-exploitation'
    },
    MOBILE: {
        label: 'Mobile',
        icon: Smartphone,
        description: 'Android and iOS assessment'
    },
    UTILITIES: {
        label: 'Utilities',
        icon: Wrench,
        description: 'Scanning, encoding, and transfer tools'
    }
};

export const CATEGORY_ORDER = [
    'WEB',
    'WINDOWS',
    'LINUX',
    'MOBILE',
    'UTILITIES'
];

export const SUBCATEGORIES: Record<string, string[]> = {
    WEB: [
        'XSS',
        'SQLi',
        'NoSQLi',
        'SSTI',
        'File Inclusion',
        'XXE',
        'CSRF',
        'SSRF',
        'Web Shells',
        'Shells & Payloads',
        'Data Manipulation',
        'JWT',
        'Subdomain Enum',
        'Fingerprinting'
    ],
    WINDOWS: [
        'Enumeration',
        'Exfiltration',
        'Evasion'
    ],
    LINUX: [
        'Enumeration'
    ],
    MOBILE: [
        'Android'
    ],
    UTILITIES: [
        'Network Scanning',
        'Vulnerability Research',
        'File Transfer',
        'Encoding'
    ]
};
