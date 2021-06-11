/* eslint-disable no-console */
/* eslint-disable security/detect-child-process */
const Process = require('child_process');
const OS = require('os');

const fixedVulnerabilities = ['CVE-2017-18924'];

(() => {
  try {
    Process.execSync('yarn audit --json').toString('utf8').split(OS.EOL);
    console.log('Audit OK!');
  } catch (err) {
    if (Array.isArray(err?.output)) {
      const vulnerabilities = err.output.reduce((acc, current) => {
        if (!current) {
          return acc;
        }

        return [
          ...acc,
          ...current
            .toString('utf8')
            .split(OS.EOL)
            .reduce((lineAcc, line) => {
              if (!line || line === '') {
                return lineAcc;
              }

              const parsedLine = JSON.parse(line);
              let isFixed = false;

              parsedLine?.data?.advisory?.cves?.map((cve) => {
                if (fixedVulnerabilities.includes(cve)) {
                  isFixed = true;
                }
              });

              if (isFixed || parsedLine?.type !== 'auditAdvisory') {
                return lineAcc;
              }

              return [...lineAcc, parsedLine];
            }, [])
        ];
      }, []);

      if (vulnerabilities.length) {
        console.error('%o', vulnerabilities);
        throw new Error('Vulnerability Found!');
      }

      console.log('Audit OK!');
      return;
    }

    console.error(err);
  }
})();
