//change   _template_  to your plugin name  

var pagesList = {
    "index": {}
};


module.exports = {
    pagesList: pagesList,
    consumes: ["app", "onlykeyApi"],
    provides: ["plugin_index"],
    setup: function(options, imports, register) {
        var fired = false;

        function doSetTime(timeout) {
            // console.log("setting time")
            if (fired) return;
            setTimeout(function() {

                fired = true;
                imports.onlykeyApi.api.check(function(asd) {
                    // console.log(asd)
                });

            }, timeout);
        }

        var page = {
            view: false,
            init: function(app) {
                app.on("ok-connected", function(version) {
                    // Not text-danger. This is a success - the clock is set
                    // and OTP works - and the theme reserves red for the one
                    // state a user must not misread, a failed decrypt or a bad
                    // signature. Rendering "ready" in the error colour is the
                    // opposite of that rule. Success carries on weight here,
                    // the way the theme's own comment says it should.
                    app.$("#setTime").after("<h2 class='oa-notice'>OnlyKey Time Set<br/> OTP/2FA Authentication Ready</h2>");
                    app.$("#setTime").remove();
                });

                app.$("#setTime").click(doSetTime.bind(null, 1));
                // app.$("#setTime").click();
            }
        };

        pagesList["index"] = page;

        register(null, {
            "plugin_index": {
                pagesList: pagesList,
                init: function() {
                    // if(document.hasFocus())//firefox fix, firefox aborts onlykey request when not in focus
                    if(imports.onlykeyApi.api.extra.getBrowser() !== "Apple")
                        imports.app.on("start", doSetTime.bind(null, 2000));
                    else {
                        // console.log("index_init");
                        imports.app.onlykeyApi.api.step = function(proceed){
                            
                            imports.app.bs_modal_dialog.confirm("Continue",
                                `To continue please click 'Yes' to access OnlyKey via USB`, ["Yes"],
                                async function(cancel, ans) {
                                    if (ans == "Yes") {
                                        proceed();
                                    }
                                });

                        }
                        
                        imports.app.on("start", doSetTime.bind(null, 2000));
                    }
                        
                    
                    // else
                    // imports.app.on("start",function(){
                    //     if(imports.app.$("#setTime").length == 0)
                    //         imports.app.$(document).focus(doSetTime);    
                    // });
                }
            }
        });


    }
};