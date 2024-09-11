module.exports = {
	...require('./parse'),
	...require('./verify'),
	...require('./utils'),
};

module.exports.default = module.exports;
