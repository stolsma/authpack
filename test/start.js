/**
 * Startup vows tests for authpack
 */
 
 var exec = require('child_process').exec;
 
 var cwd = __dirname;
 
 var child = exec('vows ' + cwd + '/**/*-test.js --isolate --spec',
  function (error, stdout, stderr) {
    console.log('' + stdout);
    console.log('' + stderr);
    if (error !== null) {
      console.log('exec error: ' + error);
    }
});