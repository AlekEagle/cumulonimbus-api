import compression, { filter } from "compression";

export default compression({
  filter: (req, res) => {
    if (req.headers["x-no-compression"]) return false;
    return filter(req, res);
  },
});
