import { RequestHandler } from 'express';

function QueryStringParser(options: QueryStringParser.Options): RequestHandler {
  const parserOptions = { ...QueryStringParser.DefaultOptions, ...options };
  return (req, res, next) => {
    const queryStr = req.originalUrl.split('?')[1];
    if (queryStr === undefined) {
      next();
      return;
    }
    const queryStrValues = decodeURIComponent(queryStr).split('&'),
      queryStrObj: { [key: string]: string | boolean | number | bigint } = {};

    for (let pair of queryStrValues) {
      let keyVal = pair.split('=');
      if (keyVal[1] === undefined) {
        if (parserOptions.ignoreKeyWithNoValue) continue;
        else if (parserOptions.keyWithNoValueIsBool) {
          queryStrObj[keyVal[0]] = true;
          continue;
        } else {
          queryStrObj[keyVal[0]] = null;
          continue;
        }
      } else {
        // if all special parsing options are disabled, don't bother checking if they can be parsed.
        if (
          !parserOptions.parseBigInt &&
          !parserOptions.parseBoolean &&
          !parserOptions.parseNumbers
        ) {
          queryStrObj[keyVal[0]] = keyVal[1];
          continue;
        } else {
          // Parse as normal number
          if (parserOptions.parseNumbers && !isNaN(Number(keyVal[1]))) {
            queryStrObj[keyVal[0]] = Number(keyVal[1]);
            continue;
          }
          // Parse as BigInt
          if (parserOptions.parseBigInt && keyVal[1].match(/^[0-9]+?n$/)) {
            queryStrObj[keyVal[0]] = BigInt(
              keyVal[1].slice(0, keyVal[1].length - 1)
            );
            continue;
          }
          // Parse as boolean
          if (
            parserOptions.parseBoolean &&
            keyVal[1].match(/^(?:true|false)$/)
          ) {
            queryStrObj[keyVal[0]] = JSON.parse(keyVal[1]);
            continue;
          }
          // Fallback
          queryStrObj[keyVal[0]] = keyVal[1];
          continue;
        }
      }
    }

    req.query = queryStrObj as any;

    next();
  };
}

namespace QueryStringParser {
  export interface Options {
    keyWithNoValueIsBool?: boolean;
    ignoreKeyWithNoValue?: boolean;
    parseNumbers?: boolean;
    parseBoolean?: boolean;
    parseBigInt?: boolean;
  }

  export const DefaultOptions: Options = {
    keyWithNoValueIsBool: false,
    ignoreKeyWithNoValue: true,
    parseNumbers: true,
    parseBoolean: true,
    parseBigInt: false
  };
}

export default QueryStringParser;
