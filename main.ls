require! { express, 'body-parser', request, 'macaroons.js' }

const ARBITER_TOKEN   = process.env.ARBITER_TOKEN
const DRIVER_HOSTNAME = process.env.DRIVER_HOSTNAME
const PORT = process.env.PORT or 8080

unless ARBITER_TOKEN?
  throw new Error 'Arbiter token undefined'

unless DRIVER_HOSTNAME?
  throw new Error 'Driver hostname undefined'

# Register with arbiter and get secret
err, res, secret <-! request.post do
  url: 'http://arbiter:8080/register'
  form: token: ARBITER_TOKEN

if err? then throw err

secret = new Buffer secret, \base64

app = express!

  #..enable 'trust proxy'

  ..use express.static 'static'

  ..use body-parser.urlencoded extended: false

  ..use (req, res, next) !->
    res.header 'Access-Control-Allow-Origin' \*
    next!

  ..get '/' (req, res) !-> res.send '// TODO: Disable UI for containers with no UI'

  ..get '/status' (req, res) !-> res.send \active

  ..post '/*' (req, res) !->
    unless req.body.macaroon?
      res.status 400 .send 'Missing macaroon'
      return

    console.log "Host: #{req.headers.host}, IP: #{req.ip}"

    mcrn = macaroons.MacaroonsBuilder.deserialize req.body.macaroon

    console.log "Macaroon:" mcrn

    verifier = new macaroons.MacaroonsVerifier mcrn
      ..satisfy-exact "target = #DRIVER_HOSTNAME.store"
      # TODO: Verify expiry and permissions here

    unless verifier.is-valid secret
      res.status 403 .send 'Invalid macaroon'
      return

    delete req.body.macaroon

    request.post do
      url: "http://#DRIVER_HOSTNAME:8080/#{req.params[0]}"
      form: req.body
    .pipe res

  ..listen PORT
