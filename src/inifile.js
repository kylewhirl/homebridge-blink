const fs = require('fs');
const os = require('os');

function escapeRegex(text) {
    return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

class IniFile {
    static parse(data, sectionName) {
        const result = new Map();
        const [, , section] = new RegExp(`(\\[${sectionName}\\])([^\\[]*)\\[?`, 'm').exec(data) || ['', '', ''];

        for (const line of section.split(/[\r\n]+/m)) {
            const [name, ...value] = line.trim().split(/=/);
            if (name) {
                result.set(name.trim(), value.join('=').trim());
            }
        }
        return Object.fromEntries(result);
    }

    static read(filePath, sectionName) {
        const result = {};
        if (!filePath || !sectionName) return result;

        filePath = filePath.replace(/^~/, os.homedir());
        if (!fs.existsSync(filePath)) return result;

        const ini = fs.readFileSync(filePath, 'utf8');
        return IniFile.parse(ini, sectionName);
    }

    static write(filePath, sectionName, data = {}) {
        if (!filePath || !sectionName) return;

        filePath = filePath.replace(/^~/, os.homedir());
        const entries = Object.entries(data)
            .filter(([, value]) => value !== undefined && value !== null && value !== '');

        const rendered = entries
            .map(([key, value]) => {
                if (typeof value === 'object') return `${key}=${JSON.stringify(value)}`;
                return `${key}=${value}`;
            })
            .join('\n');

        let iniContent = '';
        if (fs.existsSync(filePath)) {
            iniContent = fs.readFileSync(filePath, 'utf8');
        }

        const sectionHeader = `[${sectionName}]`;
        const safeSection = escapeRegex(sectionName);
        const sectionPattern = ['(^|\\n)\\[', safeSection, '\\]\\n', '[\\s\\S]*?(?=\\n\\[|$)'].join('');
        const sectionRegex = new RegExp(sectionPattern, 'm');

        if (sectionRegex.test(iniContent)) {
            iniContent = iniContent.replace(sectionRegex, `\n${sectionHeader}\n${rendered}\n`);
        }
        else {
            const prefix = iniContent.trim().length > 0 ? `${iniContent.trimEnd()}\n\n` : '';
            iniContent = `${prefix}${sectionHeader}\n${rendered}\n`;
        }

        fs.writeFileSync(filePath, iniContent);
    }
}

module.exports = IniFile;
