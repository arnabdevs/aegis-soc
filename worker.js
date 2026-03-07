export default {
  async fetch(request) {
    const url = new URL(request.url);
    url.hostname = 'aegis-soc-engine.onrender.com';
    url.protocol = 'https:';
    return fetch(new Request(url, request));
  }
}
