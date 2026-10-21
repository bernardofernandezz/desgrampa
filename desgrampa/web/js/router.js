// Navegação por hash (#varredura, #dispositivos, #relatorios/<nome>, #configuracoes).
export const PAGES = ["varredura", "dispositivos", "relatorios", "configuracoes"];

export function route() {
  const [page, ...rest] = location.hash.replace(/^#/, "").split("/");
  return { page: PAGES.includes(page) ? page : "varredura", arg: rest.join("/") };
}

export function go(hash) {
  if (location.hash !== hash) location.hash = hash;
  else window.dispatchEvent(new HashChangeEvent("hashchange"));
}
