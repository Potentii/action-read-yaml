export default class JsonPath{

	/**
	 *
	 * @param {*} val
	 * @param {string} [key]
	 * @param {{ key: string, value: * }[]} [tokens]
	 * @returns {{ key: string, value: * }[]}
	 */
	static getTokens(val, key = '$', tokens = []){

		tokens.push({ key: key, value: val });

		if(Array.isArray(val)){
			for (let i = 0; i < val.length; i++) {
				JsonPath.getTokens(val[i], `${key}[${i}]`, tokens);
			}
		} else if(typeof val == 'object'){
			for (const valKey in val) {
				if(val.hasOwnProperty(valKey)){
					JsonPath.getTokens(val[valKey], `${key}.${valKey}`, tokens);
				}
			}
		}

		return tokens;
	}

}