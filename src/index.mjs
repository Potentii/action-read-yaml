import core from '@actions/core';
import yaml from 'js-yaml';
import jp from 'jsonpath';
import * as fs from "node:fs";
import pkg from '../package.json';


const ACTION_NAME = pkg.name;
const ACTION_VERSION = pkg.version;


const filePath = core.getInput('file-path');

try {

	console.log(JSON.stringify({ level: 'info', action: ACTION_NAME, version: ACTION_VERSION, message: `Reading YAML file...`, data: { filePath: filePath } }));
	const fileContent = await fs.promises.readFile(filePath, 'utf8');
	console.log(JSON.stringify({ level: 'info', action: ACTION_NAME, version: ACTION_VERSION, message: `YAML file read was successful`, data: { filePath: filePath } }));


	console.log(JSON.stringify({ level: 'info', action: ACTION_NAME, version: ACTION_VERSION, message: `Parsing YAML file...`, data: { filePath: filePath } }));
	const yamlObject = yaml.load(fileContent);
	console.log(JSON.stringify({ level: 'info', action: ACTION_NAME, version: ACTION_VERSION, message: `YAML file parse was successful`, data: { filePath: filePath } }));


	console.log(JSON.stringify({ level: 'info', action: ACTION_NAME, version: ACTION_VERSION, message: `Parsing JSONPaths...`, data: { filePath: filePath } }));
	const jpNodes = jp.nodes(yamlObject, '$..*');

	for (let jpNode of jpNodes) {
		const key = jp.stringify(jpNode.path);
		const value = jpNode.value;

		core.setOutput(key, value);
	}

	core.setOutput('outcome', 'success');
	console.log(JSON.stringify({ level: 'info', action: ACTION_NAME, version: ACTION_VERSION, message: `JSONPath parse was successful`, data: { filePath: filePath } }));

} catch (err) {
	console.error(JSON.stringify({ level: 'error', action: ACTION_NAME, version: ACTION_VERSION, message: `Error running YAML read action`, data: { filePath: filePath }, err: { name: err.name, message: err.message, stack: err.stack } }));
	core.setOutput('outcome', 'failure');
	core.setOutput('error', err.message);
}