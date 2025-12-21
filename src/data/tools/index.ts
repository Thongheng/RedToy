import type { Tool } from '../../types';
import { WINDOWS_TOOLS } from './windows';
import { SERVICE_TOOLS } from './service';
import { WEB_TOOLS } from './web';
import { OTHER_TOOLS } from './other';
import { HACKTOOLS_REGISTRY } from './registry';

export * from './common';

export const TOOLS: Tool[] = [
    ...HACKTOOLS_REGISTRY,
    ...WINDOWS_TOOLS,
    ...SERVICE_TOOLS,
];

