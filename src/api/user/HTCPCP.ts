import { Cumulonimbus } from "../../types";
import Multer from "multer";
import Express from "express";
import ms from "ms";
import CoffeePotController, {
  Structs as CoffeePotStructs,
} from "../../utils/CoffeePotController";

const HTCPCP: Cumulonimbus.APIEndpointModule = [
  {
    method: "get",
    path: "/api/coffee-pots",
    handler: async (
      req: Cumulonimbus.Request<null, null, { limit: number; offset: number }>,
      res: Cumulonimbus.Response<
        Cumulonimbus.Structures.List<CoffeePotStructs.CoffeePot>
      >
    ) => {},
  },
];
