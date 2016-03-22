'use strict'

var request = require('request')
  , should = require('should')
var koa = require('koa')
  , session = require('koa-session')
  , route = require('koa-route')
  , mount = require('koa-mount')
  , koaqs = require('koa-qs')
var Grant = require('../../../').koa()


describe('error - koa', function () {
  function url (path) {
    var c = config.server
    return c.protocol + '://' + c.host + (c.path || '') + path
  }

  var config = {
    server: {protocol:'http', host:'localhost:5000', callback:'/'},
    facebook:{}
  }

  describe('missing middleware', function () {
    it('session', function (done) {
      var grant = new Grant(config)
      var app = koa()
      app.use(function *(next) {
        try {yield next}
        catch (err) {
          err.message.should.equal('Grant: mount session middleware first')
        }
      })
      app.use(mount(grant))
      var server = app.listen(5000, function () {
        request.get(url('/connect/facebook'), {
          jar:request.jar(),
          json:true
        }, function (err, res, body) {
          body.match(/Error: Grant: mount session middleware first/)
          server.close(done)
        })
      })
    })

    it('body-parser', function (done) {
      var grant = new Grant(config)
      var app = koa()
      app.keys = ['grant']
      app.use(session(app))
      app.use(function *(next) {
        try {yield next}
        catch (err) {
          err.message.should.equal('Grant: mount body parser middleware first')
        }
      })
      app.use(mount(grant))
      var server = app.listen(5000, function () {
        request.post(url('/connect/facebook'), {
          jar:request.jar(),
          json:true
        }, function (err, res, body) {
          body.match(/Error: Grant: mount body parser middleware first/)
          server.close(done)
        })
      })
    })
  })

  describe('oauth2', function () {
    describe('step1 - missing code', function () {
      var server
      before(function (done) {
        var grant = new Grant(config)

        var app = koa()
        app.keys = ['grant']
        app.use(session(app))
        app.use(mount(grant))
        koaqs(app)

        grant.config.facebook.authorize_url = url('/authorize_url')

        app.use(route.get('/authorize_url', function* (next) {
          this.response.redirect(url('/connect/facebook/callback?'+
            'error%5Bmessage%5D=invalid&error%5Bcode%5D=500'))
        }))
        app.use(route.get('/', function* (next) {
          this.body = JSON.stringify(this.request.query)
        }))

        server = app.listen(5000, done)
      })

      it('authorize', function (done) {
        request.get(url('/connect/facebook'), {
          jar:request.jar(),
          json:true
        }, function (err, res, body) {
          should.deepEqual(body, {error: {error:{message:'invalid', code:'500'}}})
          done()
        })
      })

      after(function (done) {
        server.close(done)
      })
    })

    describe('step1 - state mismatch', function () {
      var server
      before(function (done) {
        var grant = new Grant(config)

        var app = koa()
        app.keys = ['grant']
        app.use(session(app))
        app.use(mount(grant))
        koaqs(app)

        grant.config.facebook.authorize_url = url('/authorize_url')
        grant.config.facebook.state = 'Grant'

        app.use(route.get('/authorize_url', function* (next) {
          this.response.redirect(url('/connect/facebook/callback?'+
            'code=code&state=Purest'))
        }))
        app.use(route.get('/', function* (next) {
          this.body = JSON.stringify(this.request.query)
        }))

        server = app.listen(5000, done)
      })

      it('authorize', function (done) {
        request.get(url('/connect/facebook'), {
          jar:request.jar(),
          json:true
        }, function (err, res, body) {
          should.deepEqual(body, {error: {error:'Grant: OAuth2 state mismatch'}})
          done()
        })
      })

      after(function (done) {
        server.close(done)
      })
    })

    describe('step2 - error response', function () {
      var server
      before(function (done) {
        var grant = new Grant(config)

        var app = koa()
        app.keys = ['grant']
        app.use(session(app))
        app.use(mount(grant))
        koaqs(app)

        grant.config.facebook.authorize_url = url('/authorize_url')
        grant.config.facebook.access_url = url('/access_url')

        app.use(route.get('/authorize_url', function* (next) {
          this.response.redirect(url('/connect/facebook/callback?code=code'))
        }))
        app.use(route.post('/access_url', function* (next) {
          this.response.status = 500
          this.body = 'error%5Bmessage%5D=invalid&error%5Bcode%5D=500'
        }))
        app.use(route.get('/', function* (next) {
          this.body = JSON.stringify(this.request.query)
        }))

        server = app.listen(5000, done)
      })

      it('access', function (done) {
        request.get(url('/connect/facebook'), {
          jar:request.jar(),
          json:true
        }, function (err, res, body) {
          should.deepEqual(body, {error: {error:{message:'invalid', code:'500'}}})
          done()
        })
      })

      after(function (done) {
        server.close(done)
      })
    })
  })

  describe('missing provider', function () {
    var grant, server, jar = request.jar()
    before(function (done) {
      grant = new Grant(config)
      var app = koa()
      app.keys = ['grant']
      app.use(session(app))
      app.use(mount(grant))
      koaqs(app)

      app.use(route.get('/', function* (next) {
        this.response.set('x-test', true)
        this.body = JSON.stringify(this.request.query)
      }))
      server = app.listen(5000, done)
    })

    it('connect', function (done) {
      delete grant.config.facebook.oauth
      request.get(url('/connect/facebook'), {
        jar:jar,
        json:true
      }, function (err, res, body) {
        res.headers['x-test'].should.equal('true')
        should.deepEqual(body, {
          error: 'Grant: missing or misconfigured provider'})
        done()
      })
    })
    it('connect - no callback', function (done) {
      delete grant.config.facebook.callback
      request.get(url('/connect/facebook'), {
        jar:jar,
        json:true
      }, function (err, res, body) {
        should.equal(res.headers['x-test'], undefined)
        should.deepEqual(body, {
          error: 'Grant: missing or misconfigured provider'})
        done()
      })
    })

    it('callback', function (done) {
      grant.config.facebook.callback = '/'
      request.get(url('/connect/facebook/callback'), {
        jar:jar,
        json:true
      }, function (err, res, body) {
        res.headers['x-test'].should.equal('true')
        should.deepEqual(body, {
          error: 'Grant: missing session or misconfigured provider'})
        done()
      })
    })
    it('callback - no callback', function (done) {
      delete grant.config.facebook.callback
      request.get(url('/connect/facebook/callback'), {
        jar:jar,
        json:true
      }, function (err, res, body) {
        should.equal(res.headers['x-test'], undefined)
        should.deepEqual(body, {
          error: 'Grant: missing session or misconfigured provider'})
        done()
      })
    })

    after(function (done) {
      server.close(done)
    })
  })
})
