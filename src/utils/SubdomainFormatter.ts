export default function SubdomainFormatter(subdomain: string): string {
  return subdomain
    .trim() // Remove leading and trailing whitespace (this should be taken care of by the endpoint already, but just in case)
    .toLowerCase() // Convert the subdomain to lowercase
    .replace(/\s/g, "-") // Replace whitespace with dashes
    .replace(/[^a-z0-9-]/g, "") // Remove any non-alphanumeric characters
    .replace(/-+/g, "-") // Replace multiple dashes with a single dash
    .replace(/^-/, "") // Remove any leading dashes
    .replace(/-$/, ""); // Remove any trailing dashes
}
