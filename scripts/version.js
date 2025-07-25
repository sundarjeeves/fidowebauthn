#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// Version increment types
const VERSION_TYPES = {
    PATCH: 'patch',  // 1.0.0 -> 1.0.1 (bug fixes)
    MINOR: 'minor',  // 1.0.0 -> 1.1.0 (new features)
    MAJOR: 'major'   // 1.0.0 -> 2.0.0 (breaking changes)
};

function incrementVersion(currentVersion, type = 'patch') {
    const [major, minor, patch] = currentVersion.split('.').map(Number);
    
    switch (type) {
        case 'major':
            return `${major + 1}.0.0`;
        case 'minor':
            return `${major}.${minor + 1}.0`;
        case 'patch':
        default:
            return `${major}.${minor}.${patch + 1}`;
    }
}

function updatePackageJson(version) {
    const packagePath = path.join(__dirname, '..', 'package.json');
    const packageJson = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
    
    packageJson.version = version;
    
    fs.writeFileSync(packagePath, JSON.stringify(packageJson, null, 2) + '\n');
    console.log(`✅ Updated package.json version to ${version}`);
}

function main() {
    const type = process.argv[2] || 'patch';
    
    if (!Object.values(VERSION_TYPES).includes(type)) {
        console.error(`❌ Invalid version type: ${type}`);
        console.error(`Valid types: ${Object.values(VERSION_TYPES).join(', ')}`);
        process.exit(1);
    }
    
    const packagePath = path.join(__dirname, '..', 'package.json');
    const packageJson = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
    const currentVersion = packageJson.version;
    
    console.log(`📦 Current version: ${currentVersion}`);
    
    const newVersion = incrementVersion(currentVersion, type);
    console.log(`🆕 New version: ${newVersion}`);
    
    updatePackageJson(newVersion);
    
    console.log(`\n🎉 Version updated successfully!`);
    console.log(`📝 Next time you restart the server, the footer will show version ${newVersion}`);
}

if (require.main === module) {
    main();
}

module.exports = { incrementVersion, updatePackageJson }; 