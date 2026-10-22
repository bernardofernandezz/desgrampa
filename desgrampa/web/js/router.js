// Navegação por hash (#varredura, #dispositivos, #relatorios/<nome>[/achado/<n>], #atendimento, #ajuda, #configuracoes).
export const PAGES = ["varredura", "dispositivos", "relatorios", "atendimento", "ajuda", "configuracoes"];

export function route() {
  const [page, ...rest] = location.hash.replace(/^#/, "").split("/");
  return { page: PAGES.includes(page) ? page : "varredura", arg: rest.join("/") };
}

export function go(hash) {
  if (location.hash !== hash) location.hash = hash;
  else window.dispatchEvent(new HashChangeEvent("hashchange"));
}
