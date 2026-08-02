import { describe, it, expect } from 'vitest';
import { parseLockfile, LOCKFILE_PARSERS } from '../../src/analyzers/osv-lockfiles.js';

describe('parseLockfile', () => {
  it('parses pinned requirements.txt lines and ignores the rest', () => {
    const content = [
      'requests==2.31.0',
      'flask == 2.0.1',
      'unpinned-pkg',
      'ranged>=1.0',
      '# comment',
      '-r other.txt',
      'extras[sec]==1.2.3',
    ].join('\n');
    expect(parseLockfile('requirements.txt', content)).toEqual([
      { ecosystem: 'PyPI', name: 'requests', version: '2.31.0' },
      { ecosystem: 'PyPI', name: 'flask', version: '2.0.1' },
      { ecosystem: 'PyPI', name: 'extras', version: '1.2.3' },
    ]);
  });

  it('parses poetry.lock package blocks', () => {
    const content = `
[[package]]
name = "django"
version = "4.2.1"
description = "x"

[[package]]
name = "urllib3"
version = "1.26.5"
`;
    expect(parseLockfile('poetry.lock', content)).toEqual([
      { ecosystem: 'PyPI', name: 'django', version: '4.2.1' },
      { ecosystem: 'PyPI', name: 'urllib3', version: '1.26.5' },
    ]);
  });

  it('parses Pipfile.lock default and develop sections', () => {
    const content = JSON.stringify({
      default: { requests: { version: '==2.19.0' } },
      develop: { pytest: { version: '==7.0.0' }, editable: { path: '.' } },
    });
    expect(parseLockfile('Pipfile.lock', content)).toEqual([
      { ecosystem: 'PyPI', name: 'requests', version: '2.19.0' },
      { ecosystem: 'PyPI', name: 'pytest', version: '7.0.0' },
    ]);
  });

  it('parses Cargo.lock package blocks', () => {
    const content = `
[[package]]
name = "serde"
version = "1.0.100"
source = "registry"

[[package]]
name = "time"
version = "0.1.45"
`;
    expect(parseLockfile('Cargo.lock', content)).toEqual([
      { ecosystem: 'crates.io', name: 'serde', version: '1.0.100' },
      { ecosystem: 'crates.io', name: 'time', version: '0.1.45' },
    ]);
  });

  it('parses go.mod require blocks and single-line requires, skipping indirect-only markers', () => {
    const content = `
module example.com/app

go 1.22

require (
\tgithub.com/gin-gonic/gin v1.9.0
\tgolang.org/x/text v0.3.7 // indirect
)

require github.com/pkg/errors v0.9.1
`;
    expect(parseLockfile('go.mod', content)).toEqual([
      { ecosystem: 'Go', name: 'github.com/gin-gonic/gin', version: '1.9.0' },
      { ecosystem: 'Go', name: 'golang.org/x/text', version: '0.3.7' },
      { ecosystem: 'Go', name: 'github.com/pkg/errors', version: '0.9.1' },
    ]);
  });

  it('parses composer.lock packages and dev packages', () => {
    const content = JSON.stringify({
      packages: [{ name: 'monolog/monolog', version: '2.0.0' }],
      'packages-dev': [{ name: 'phpunit/phpunit', version: 'v9.5.0' }],
    });
    expect(parseLockfile('composer.lock', content)).toEqual([
      { ecosystem: 'Packagist', name: 'monolog/monolog', version: '2.0.0' },
      { ecosystem: 'Packagist', name: 'phpunit/phpunit', version: '9.5.0' },
    ]);
  });

  it('parses Gemfile.lock GEM specs', () => {
    const content = `
GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.4)
      actionpack (= 7.0.4)
    nokogiri (1.13.10)

PLATFORMS
  ruby
`;
    expect(parseLockfile('Gemfile.lock', content)).toEqual([
      { ecosystem: 'RubyGems', name: 'rails', version: '7.0.4' },
      { ecosystem: 'RubyGems', name: 'nokogiri', version: '1.13.10' },
    ]);
  });

  it('returns [] for unknown filenames and malformed content', () => {
    expect(parseLockfile('random.txt', 'whatever')).toEqual([]);
    expect(parseLockfile('composer.lock', 'not json')).toEqual([]);
    expect(parseLockfile('Pipfile.lock', '{{{{')).toEqual([]);
  });

  it('exposes the supported lockfile names', () => {
    expect(Object.keys(LOCKFILE_PARSERS)).toEqual(
      expect.arrayContaining([
        'requirements.txt',
        'poetry.lock',
        'Pipfile.lock',
        'Cargo.lock',
        'go.mod',
        'composer.lock',
        'Gemfile.lock',
      ]),
    );
  });
});
