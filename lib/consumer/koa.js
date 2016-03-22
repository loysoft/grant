'use strict'

var convert = require('koa-convert')
  , thunkify = require('thunkify')

var qs = require('qs')

var config = require('../config')
var f = {
  1: require('../flow/oauth1'),
  2: require('../flow/oauth2'),
  3: require('../flow/getpocket')
}
var flows = {
  1:{step1:thunkify(f[1].step1), step2:f[1].step2, step3:thunkify(f[1].step3)},
  2:{step1:f[2].step1, step2:thunkify(f[2].step2), step3:f[2].step3},
  getpocket:{step1:thunkify(f[3].step1), step2:f[3].step2, step3:thunkify(f[3].step3)}
}


function Grant (app, _config) {
  app.grantConfig = config.init(_config)
  app.grantConfigOrig = _config

  app.all('/connect/:provider/:override?', convert(function *(next) {
    if (!this.session)
      throw new Error('Grant: mount session middleware first')
    if (this.method == 'POST' && !this.request.body)
      throw new Error('Grant: mount body parser middleware first')
    yield next
  }))

  app.get('/connect/:provider/:override?', convert(function *() {
    var provider = this.params.provider
    var override = this.params.override

    if (override == 'callback') return yield callback

    this.session.grant = {
      provider:provider
    }
    if (override) {
      this.session.grant.override = override
    }
    if (Object.keys(this.request.query||{}).length) {
      this.session.grant.dynamic = this.request.query
    }

    yield connect
  }))

  app.post('/connect/:provider/:override?', convert(function *() {
    var provider = this.params.provider
    var override = this.params.override
    this.session.grant = {
      provider:provider
    }
    if (override) {
      this.session.grant.override = override
    }
    if (Object.keys(this.request.body||{}).length) {
      this.session.grant.dynamic = this.request.body
    }

    yield connect
  }))

  function* connect () {
    var grant = this.session.grant
    var provider = config.provider(app.grantConfig, grant)
    var flow = flows[provider.oauth]
    var callbackPath = (provider.path || '') + provider.callback


    if (provider.oauth == 1) {
      var data
      try {
        data = yield flow.step1(provider)
      } catch (err) {
        return this.response.redirect(callbackPath + '?' + err)
      }
      grant.step1 = data
      var url = flow.step2(provider, data)
      this.response.redirect(url)
    }

    else if (provider.oauth == 2) {
      grant.state = provider.state
      var url = flow.step1(provider)
      this.response.redirect(url)
    }

    else if (flow) {
      try {
        var data = yield flow.step1(provider)
      } catch (err) {
        return this.response.redirect(callbackPath+ '?' + err)
      }
      grant.step1 = data
      var url = flow.step2(provider, data)
      this.response.redirect(url)
    }

    else {
      var err = {error:'Grant: missing or misconfigured provider'}
      if (callbackPath) {
        this.response.redirect(callbackPath + '?' + qs.stringify(err))
      } else {
        this.body = JSON.stringify(err)
      }
    }
  }

  function* callback () {
    var grant = this.session.grant || {}
    var provider = config.provider(app.grantConfig, grant)
    var flow = flows[provider.oauth]
    var callbackPath = (provider.path || '') + provider.callback

    var callback = function (response) {
      if (!provider.transport || provider.transport == 'querystring') {
        this.response.redirect(callbackPath + '?' + response)
      }
      else if (provider.transport == 'session') {
        this.session.grant.response = qs.parse(response)
        this.response.redirect(callbackPath)
      }
    }.bind(this)

    if (provider.oauth == 1) {
      try {
        var response = yield flow.step3(provider, grant.step1, this.query)
      } catch (err) {
        return this.response.redirect(callbackPath + '?' + err)
      }
      callback(response)
    }

    else if (provider.oauth == 2) {
      try {
        var data = yield flow.step2(provider, this.query, grant)
      } catch (err) {
        return this.response.redirect(callbackPath + '?' + err)
      }
      var response = flow.step3(provider, data)
      callback(response)
    }

    else if (flow) {
      try {
        var response = yield flow.step3(provider, grant.step1)
      } catch (err) {
        return this.reponse.redirect(callbackPath + '?' + err)
      }
      callback(response)
    }

    else {
      var err = {error:'Grant: missing session or misconfigured provider'}
      if (callbackPath) {
        this.response.redirect(callbackPath + '?' + qs.stringify(err))
      } else {
        this.body = JSON.stringify(err)
      }
    }
  }

  return app
}

exports = module.exports = Grant
