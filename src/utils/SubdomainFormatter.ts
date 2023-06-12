export default function SubdomainFormatter(sd: string) {
  return sd
    .trim()
    .split("")
    .filter((a) => a.match(/[a-z0-9- ]/i))
    .join("")
    .split(/\s/g)
    .filter((a) => a !== "")
    .join("-");
}
