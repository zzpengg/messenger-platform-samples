/*
 * Copyright 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

/* jshint node: true, devel: true */
'use strict';

const 
  bodyParser = require('body-parser'),
  config = require('config'),
  crypto = require('crypto'),
  express = require('express'),
  https = require('https'), 
  http = require("http"),
  request = require('request'), 
  FB = require("fb"),
  querystring = require('querystring');

var app = express();
app.set('port', process.env.PORT || 5000);
app.set('view engine', 'ejs');
app.use(bodyParser.json({ verify: verifyRequestSignature }));
app.use(express.static('public'));

/*
 * Be sure to setup your config values before running this code. You can 
 * set them using environment variables or modifying the config file in /config.
 *
 */

// App Secret can be retrieved from the App Dashboard
const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ? 
  process.env.MESSENGER_APP_SECRET :
  config.get('appSecret');

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
  (process.env.MESSENGER_VALIDATION_TOKEN) :
  config.get('validationToken');

// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
  (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
  config.get('pageAccessToken');

// URL where the app is running (include protocol). Used to point to scripts and 
// assets located at this address. 
const SERVER_URL = (process.env.SERVER_URL) ?
  (process.env.SERVER_URL) :
  config.get('serverURL');

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL)) {
  console.error("Missing config values");
  process.exit(1);
}

/*
 * Use your own validation token. Check that the token used in the Webhook 
 * setup is the same token used here.
 *
 */
app.get('/webhook', function(req, res) {
  if (req.query['hub.mode'] === 'subscribe' &&
      req.query['hub.verify_token'] === VALIDATION_TOKEN) {
    console.log("Validating webhook");
    res.status(200).send(req.query['hub.challenge']);
  } else {
    console.error("Failed validation. Make sure the validation tokens match.");
    res.sendStatus(403);          
  }  
});


/*
 * All callbacks for Messenger are POST-ed. They will be sent to the same
 * webhook. Be sure to subscribe your app to your page to receive callbacks
 * for your page. 
 * https://developers.facebook.com/docs/messenger-platform/product-overview/setup#subscribe_app
 *
 */
app.post('/webhook', function (req, res) {
  var data = req.body;

  // Make sure this is a page subscription
  if (data.object == 'page') {
    // Iterate over each entry
    // There may be multiple if batched
    data.entry.forEach(function(pageEntry) {
      var pageID = pageEntry.id;
      var timeOfEvent = pageEntry.time;

      // Iterate over each messaging event
      pageEntry.messaging.forEach(function(messagingEvent) {
        if (messagingEvent.optin) {
          receivedAuthentication(messagingEvent);
        } else if (messagingEvent.message) {
          receivedMessage(messagingEvent);
        } else if (messagingEvent.delivery) {
          receivedDeliveryConfirmation(messagingEvent);
        } else if (messagingEvent.postback) {
          receivedPostback(messagingEvent);
        } else if (messagingEvent.read) {
          receivedMessageRead(messagingEvent);
        } else if (messagingEvent.account_linking) {
          receivedAccountLink(messagingEvent);
        } else {
          console.log("Webhook received unknown messagingEvent: ", messagingEvent);
        }
      });
    });

    // Assume all went well.
    //
    // You must send back a 200, within 20 seconds, to let us know you've 
    // successfully received the callback. Otherwise, the request will time out.
    res.sendStatus(200);
  }
});

/*
 * This path is used for account linking. The account linking call-to-action
 * (sendAccountLinking) is pointed to this URL. 
 * 
 */
app.get('/authorize', function(req, res) {
  var accountLinkingToken = req.query['account_linking_token'];
  var redirectURI = req.query['redirect_uri'];

  // Authorization Code should be generated per user by the developer. This will 
  // be passed to the Account Linking callback.
  var authCode = "1234567890";

  // Redirect users to this URI on successful login
  var redirectURISuccess = redirectURI + "&authorization_code=" + authCode;

  res.render('authorize', {
    accountLinkingToken: accountLinkingToken,
    redirectURI: redirectURI,
    redirectURISuccess: redirectURISuccess
  });
});

/*
 * Verify that the callback came from Facebook. Using the App Secret from 
 * the App Dashboard, we can verify the signature that is sent with each 
 * callback in the x-hub-signature field, located in the header.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
  var signature = req.headers["x-hub-signature"];

  if (!signature) {
    // For testing, let's log an error. In production, you should throw an 
    // error.
    console.error("Couldn't validate the signature.");
  } else {
    var elements = signature.split('=');
    var method = elements[0];
    var signatureHash = elements[1];

    var expectedHash = crypto.createHmac('sha1', APP_SECRET)
                        .update(buf)
                        .digest('hex');

    if (signatureHash != expectedHash) {
      throw new Error("Couldn't validate the request signature.");
    }
  }
}

/*
 * Authorization Event
 *
 * The value for 'optin.ref' is defined in the entry point. For the "Send to 
 * Messenger" plugin, it is the 'data-ref' field. Read more at 
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/authentication
 *
 */
function receivedAuthentication(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfAuth = event.timestamp;

  // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
  // The developer can set this to an arbitrary value to associate the 
  // authentication callback with the 'Send to Messenger' click event. This is
  // a way to do account linking when the user clicks the 'Send to Messenger' 
  // plugin.
  var passThroughParam = event.optin.ref;

  console.log("Received authentication for user %d and page %d with pass " +
    "through param '%s' at %d", senderID, recipientID, passThroughParam, 
    timeOfAuth);

  // When an authentication is received, we'll send a message back to the sender
  // to let them know it was successful.
  sendTextMessage(senderID, "Authentication successful");
}

/*
 * Message Event
 *
 * This event is called when a message is sent to your page. The 'message' 
 * object format can vary depending on the kind of message that was received.
 * Read more at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-received
 *
 * For this example, we're going to echo any text that we get. If we get some 
 * special keywords ('button', 'generic', 'receipt'), then we'll send back
 * examples of those bubbles to illustrate the special message bubbles we've 
 * created. If we receive a message with an attachment (image, video, audio), 
 * then we'll simply confirm that we've received the attachment.
 * 
 */
 
  //var user = {};
  var start = {};//查詢是否開始
  var step = {};//查詢到第幾個步驟了
  var query_count = {};
  
  //儲存搜尋項目
  var search = {};
  var req = [];
  var pattern = {
    "": "無",
    "N": "未輸入",
    "M": "公",
    "F": "母",
    "MINI": "迷你",
    "SMALL": "小型",
    "MEDIUM": "中型",
    "BIG": "大型",
    "NONE": "未公告",
    "OPEN": "開放認養",
    "ADOPTED": "已認養",
    "OTHER": "其他",
    "DEAD": "死亡",
    "CHILD": "幼年",
    "ADULT": "成年"
    };
  var _pattern = {
    "N": "未輸入",
    "T": "是",
    "F": "否",
    "CHILD": "否",
    "ADULT": "是"
  }
 
function receivedMessage(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfMessage = event.timestamp;
  var message = event.message;

  console.log("Received message for user %d and page %d at %d with message:", 
    senderID, recipientID, timeOfMessage);
  console.log(JSON.stringify(message));

  var isEcho = message.is_echo;
  var messageId = message.mid;
  var appId = message.app_id;
  var metadata = message.metadata;

  // You may get a text or attachment but not both
  var messageText = message.text;
  var messageAttachments = message.attachments;
  var quickReply = message.quick_reply;

  if (isEcho) {
    // Just logging message echoes to console
    console.log("Received echo for message %s and app %d with metadata %s", 
      messageId, appId, metadata);
    return;
  } else if (quickReply) {
    var quickReplyPayload = quickReply.payload;
    console.log("Quick reply for message %s with payload %s",
      messageId, quickReplyPayload);

    sendTextMessage(senderID, "Quick reply tapped");
    return;
  }


  


  if (messageText) {
    if (typeof search[senderID] == 'undefined')
      search[senderID] = {};
    // If we receive a text message, check to see if it matches any special
    // keywords and send back the corresponding example. Otherwise, just echo
    // the text we received.
    if(start[senderID] != 87 ){
      switch (messageText) {
        case '開始':
          sendTextMessage(senderID, "查詢開始！\n接下來的問題如果你覺得無所謂都可以，請回答[都可]兩字");
          setTimeout(function(){ sendTextMessage(senderID, "你的預算多少？\n（EX：5000）"); }, 2000);
          start[senderID] = 87;
          step[senderID] = 1;
          break;
        default:
          sendTextMessage(senderID, "你好！我是彰師租屋的小幫手，我可以幫助你查詢你想要租的房子喔！\n只要輸入[開始]這兩個字就能開始查詢~ ");
      }
    } else if(start[senderID]==87){
      if(step[senderID] == 1){//取得動物類型
        search[senderID].kind = messageText;
        sendQuickReply(senderID, "租金", ["小於4000", "4000~6000" , "6000以上"]);
        step[senderID] = 2;
      } else if(step[senderID] == 2){//取得動物性別
        search[senderID].sex = messageText;
        sendTextMessage(senderID, "寵物的體型？\n（迷你 / 大型 / 中型 / 小型）");
        step[senderID] = 3;
      } else if(step[senderID] == 3){//取得動物體型
        search[senderID].bodytype = messageText;
        sendTextMessage(senderID, "寵物是否成年？\n（是 / 否）");
        step[senderID] = 4;
      } else if(step[senderID] == 4){//取得動物年紀
        search[senderID].age = messageText;
        sendTextMessage(senderID, "寵物的毛色？\n（簡短比較有利搜尋）");
        step[senderID] = 5;
      } else if(step[senderID] == 5){//取得動物毛色
        search[senderID].colour = messageText;
        sendTextMessage(senderID, "寵物所在的地點？\n（簡短比較有利搜尋）");
        step[senderID] = 6;
      } else if(step[senderID] == 6){//取得動物地點
        search[senderID].place = messageText;
        sendTextMessage(senderID, "詢問完成、開始查詢~~~");
        query_count[senderID] = 0;
        req = "";
        var _request = http.get("http://data.coa.gov.tw/Service/OpenData/AnimalOpenData.aspx", function(response) {
          response.on('data', function (chunk) {
            req += chunk;
          });
          response.on('end', function() {
            req = JSON.parse(req);
            sendTextMessage(senderID, "搜尋結果如下：");
            setTimeout(function(){ find(senderID); }, 2000);
            step[senderID] = 7;
          });
        });
        _request.on("error", function(err) {
          console.log(err);
        });
      } else if(step[senderID] == 7){
        if (messageText == '確認領養') {
          autoPost(req, query_count[senderID])
        }
        if (messageText == '是')
          find(senderID);
        else {
          step[senderID] = 0;
          start[senderID]=0;
          sendTextMessage(senderID, "你好！我是動物領養資訊站的小幫手，我可以幫助你查詢適合你領養的寵物喔！\n只要輸入[開始]這兩個字就能開始查詢~ ");
        }
      }
    } 
    
  } else if (messageAttachments) {
    sendTextMessage(senderID, "怕.jpg");
  }
}

function find(senderID) {
  for (var i = query_count[senderID], c = 0; i < req.length; i++, c = 0) {
    if (search[senderID].kind == "都可" || req[i].animal_kind.match(search[senderID].kind) != null)
      c++;
    if (search[senderID].sex == "都可" || pattern[req[i].animal_sex] == search[senderID].sex)
      c++;
    if (search[senderID].bodytype == "都可" || pattern[req[i].animal_bodytype] == search[senderID].bodytype)
      c++;
    if (search[senderID].age == "都可" || _pattern[req[i].animal_age] == search[senderID].age)
      c++;
    if (search[senderID].colour == "都可" || req[i].animal_colour.match(search[senderID].colour) != null)
      c++;
    if (search[senderID].place == "都可" || req[i].animal_place.match(search[senderID].place) != null)
      c++;
    if (c == 6)
    {
      query_count[senderID] = i+1;
      c = 0;
      sendImageMessage(senderID, req[i].album_file);
      setTimeout(function(){ sendTextMessage(senderID, req[i].animal_remark); }, 2000);
      setTimeout(function(){ sendTextMessage(senderID, "小檔案\n動物編號：" + req[i].animal_id + "\n區域編號：" + req[i].animal_subid + "\n狀態：" + pattern[req[i].animal_status] + "\n類型：" + req[i].animal_kind + "\n性別：" + pattern[req[i].animal_sex] + "\n體型：" + pattern[req[i].animal_bodytype] + "\n年紀：" + pattern[req[i].animal_age] + "\n毛色：" + req[i].animal_colour + "\n尋獲地點：" + req[i].animal_foundplace + "\n目前所在地點：" + req[i].animal_place + "\n是否結紮：" + _pattern[req[i].animal_sterilization] + "\n是否已施打狂犬病疫苗：" + _pattern[req[i].animal_bacterin] + "\n開放認養起始日期：" + req[i].animal_opendate + "\n開放認養截止日期：" + req[i].animal_closeddate + "\n資料更新日期：" + req[i].animal_update); }, 4000);
      setTimeout(function(){ sendTextMessage(senderID, "聯絡資訊\n收容所名稱：" + req[i].shelter_name + "\n收容所地址：" + req[i].shelter_address + "\n聯絡電話：" + req[i].shelter_tel); }, 6000);
      setTimeout(function(){ sendTextMessage(senderID, "是否顯示下一筆資料？（是 / 否）, 若想領養該寵物 請輸入 [確認領養] 我們將結束搜尋並發文~~"); }, 8000);
      return;
    }
  }
  sendTextMessage(senderID, "已無符合搜尋條件的寵物了");
  step[senderID] = 0;
  start[senderID]=0;
}

/*
 * Delivery Confirmation Event
 *
 * This event is sent to confirm the delivery of a message. Read more about 
 * these fields at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-delivered
 *
 */
function receivedDeliveryConfirmation(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var delivery = event.delivery;
  var messageIDs = delivery.mids;
  var watermark = delivery.watermark;
  var sequenceNumber = delivery.seq;

  if (messageIDs) {
    messageIDs.forEach(function(messageID) {
      console.log("Received delivery confirmation for message ID: %s", 
        messageID);
    });
  }

  console.log("All message before %d were delivered.", watermark);
}


/*
 * Postback Event
 *
 * This event is called when a postback is tapped on a Structured Message. 
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/postback-received
 * 
 */
function receivedPostback(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfPostback = event.timestamp;

  // The 'payload' param is a developer-defined field which is set in a postback 
  // button for Structured Messages. 
  var payload = event.postback.payload;

  console.log("Received postback for user %d and page %d with payload '%s' " + 
    "at %d", senderID, recipientID, payload, timeOfPostback);

  // When a postback is called, we'll send a message back to the sender to 
  // let them know it was successful
  sendTextMessage(senderID, "Postback called");
}

/*
 * Message Read Event
 *
 * This event is called when a previously-sent message has been read.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-read
 * 
 */
function receivedMessageRead(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  // All messages before watermark (a timestamp) or sequence have been seen.
  var watermark = event.read.watermark;
  var sequenceNumber = event.read.seq;

  console.log("Received message read event for watermark %d and sequence " +
    "number %d", watermark, sequenceNumber);
}

/*
 * Account Link Event
 *
 * This event is called when the Link Account or UnLink Account action has been
 * tapped.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/account-linking
 * 
 */
function receivedAccountLink(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  var status = event.account_linking.status;
  var authCode = event.account_linking.authorization_code;

  console.log("Received account link event with for user %d with status %s " +
    "and auth code %s ", senderID, status, authCode);
}

/*
 * 傳送寵物圖片
 *
 */
function sendImageMessage(recipientId, query_url) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: query_url
        }
      }
    }
  };

  callSendAPI(messageData);
}


/*
 * Send a Gif using the Send API.
 *
 */
function sendGifMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: SERVER_URL + "/assets/instagram_logo.gif"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send audio using the Send API.
 *
 */
function sendAudioMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "audio",
        payload: {
          url: SERVER_URL + "/assets/sample.mp3"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a video using the Send API.
 *
 */
function sendVideoMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "video",
        payload: {
          url: SERVER_URL + "/assets/allofus480.mov"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a video using the Send API.
 *
 */
function sendFileMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "file",
        payload: {
          url: SERVER_URL + "/assets/test.txt"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(recipientId, messageText) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: messageText,
      metadata: "DEVELOPER_DEFINED_METADATA"
    }
  };

  callSendAPI(messageData);
}

/*/////////////////////////////////////////////////////////////////////////////////////////
 * 回傳寵物資訊
 *
 */
function sendResultMessage(recipientId, query_text) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: query_text,
          buttons:[{
            type: "phone_number",//電話
            title: "Call Phone Number",
            payload: "+16505551234"
          }]
        }
      }
    }
  };  

  callSendAPI(messageData);
}

/*
 * Send a Structured Message (Generic Message type) using the Send API.
 *
 */
function sendgenericMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "generic",
          elements: [{
            title: "寵物",
            subtitle: "寵物說明",
            image_url: "https://cdn.free.com.tw/blog/wp-content/uploads/2014/08/Placekitten480-g.jpg",//放圖片
            text: "用很多text來講寵物資訊",
            buttons: [{
              type: "phone_number",
              title: "馬上聯絡我",
              payload: "+16505551234",//電話號碼
            }],
          }]
        }
      }
    }
  };  

  callSendAPI(messageData);
}

/*
 * Send a receipt message using the Send API.
 *
 */
function sendReceiptMessage(recipientId) {
  // Generate a random receipt ID as the API requires a unique ID
  var receiptId = "order" + Math.floor(Math.random()*1000);

  var messageData = {
    recipient: {
      id: recipientId
    },
    message:{
      attachment: {
        type: "template",
        payload: {
          template_type: "receipt",
          recipient_name: "Peter Chang",
          order_number: receiptId,
          currency: "USD",
          payment_method: "Visa 1234",        
          timestamp: "1428444852", 
          elements: [{
            title: "Oculus Rift",
            subtitle: "Includes: headset, sensor, remote",
            quantity: 1,
            price: 599.00,
            currency: "USD",
            image_url: SERVER_URL + "/assets/riftsq.png"
          }, {
            title: "Samsung Gear VR",
            subtitle: "Frost White",
            quantity: 1,
            price: 99.99,
            currency: "USD",
            image_url: SERVER_URL + "/assets/gearvrsq.png"
          }],
          address: {
            street_1: "1 Hacker Way",
            street_2: "",
            city: "Menlo Park",
            postal_code: "94025",
            state: "CA",
            country: "US"
          },
          summary: {
            subtotal: 698.99,
            shipping_cost: 20.00,
            total_tax: 57.67,
            total_cost: 626.66
          },
          adjustments: [{
            name: "New Customer Discount",
            amount: -50
          }, {
            name: "$100 Off Coupon",
            amount: -100
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a message with Quick Reply buttons.
 *
 */
function sendQuickReply(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: "What's your favorite movie genre?",
      metadata: "DEVELOPER_DEFINED_METADATA",
      quick_replies: [
        {
          "content_type":"text",
          "title":"Action",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_ACTION"
        },
        {
          "content_type":"text",
          "title":"Comedy",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_COMEDY"
        },
        {
          "content_type":"text",
          "title":"Drama",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_DRAMA"
        }
      ]
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a read receipt to indicate the message has been read
 *
 */
function sendReadReceipt(recipientId) {
  console.log("Sending a read receipt to mark message as seen");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "mark_seen"
  };

  callSendAPI(messageData);
}

/*
 * Turn typing indicator on
 *
 */
function sendTypingOn(recipientId) {
  console.log("Turning typing indicator on");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "typing_on"
  };

  callSendAPI(messageData);
}

/*
 * Turn typing indicator off
 *
 */
function sendTypingOff(recipientId) {
  console.log("Turning typing indicator off");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "typing_off"
  };

  callSendAPI(messageData);
}

/*
 * Send a message with the account linking call-to-action
 *
 */
function sendAccountLinking(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Welcome. Link your account.",
          buttons:[{
            type: "account_link",
            url: SERVER_URL + "/authorize"
          }]
        }
      }
    }
  };  

  callSendAPI(messageData);
}

/*
 * Call the Send API. The message data goes in the body. If successful, we'll 
 * get the message id in a response 
 *
 */
function callSendAPI(messageData) {
  request({
    uri: 'https://graph.facebook.com/v2.6/me/messages',
    qs: { access_token: PAGE_ACCESS_TOKEN },
    method: 'POST',
    json: messageData

  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      var recipientId = body.recipient_id;
      var messageId = body.message_id;

      if (messageId) {
        console.log("Successfully sent message with id %s to recipient %s", 
          messageId, recipientId);
      } else {
      console.log("Successfully called Send API for recipient %s", 
        recipientId);
      }
    } else {
      console.error(response.error);
    }
  });  
}


function autoPost(req, index) {
  //console.log('The function is start')
  var pageId = "1477720848276964"
  var token = "EAAYF0HUspqwBAOaKg4OcIVi7ON3VspUbPrhHGd1V2h3EoIry5zzNpJ0z1c7xadin66yULW7D4ZB5KXJhM1lBoDblSNQZCWODAN7JVho1lENAQY5vOsxVDCbirnqMtJoOoqAXoJRgwcc997fZCJQEDewM0R7YkZAZA786VRc95wwZDZD";
  
  FB.setAccessToken(token)
  //console.log('token was set')
  FB.api('/' + pageId, {fields: token}, function(resp) {
    //console.log('api is working')
    //if(resp.access_token) {
      console.log('api is working')
      FB.api('/' + pageId + '/feed',
        'post',
        { 
          picture: req[index - 1].album_file, // animal picture
          link: req[index - 1].album_file,
          //url: "http://ugc.qpic.cn/baikepic2/7714/20151105155440-693106979.jpg/0",
          message: "\nHello everyone I have been adopt~~~~\n\n\n小檔案\n動物編號：" + req[index - 1].animal_id + "\n區域編號：" + req[index - 1].animal_subid + "\n狀態：" + pattern[req[index - 1].animal_status] + "\n類型：" + req[index - 1].animal_kind + "\n性別：" + pattern[req[index - 1].animal_sex] + "\n體型：" + pattern[req[index - 1].animal_bodytype] + "\n年紀：" + pattern[req[index - 1].animal_age] + "\n毛色：" + req[index - 1].animal_colour + "\n尋獲地點：" + req[index - 1].animal_foundplace + "\n目前所在地點：" + req[index - 1].animal_place + "\n是否結紮：" + _pattern[req[index - 1].animal_sterilization] + "\n是否已施打狂犬病疫苗：" + _pattern[req[index - 1].animal_bacterin] + "\n",
          access_token: resp.access_token
        }
        ,function(response) {
        console.log('po po po po po po po po')
        console.log(response);
        });
      //}
    });
}

// Start server
// Webhooks must be available via SSL with a certificate signed by a valid 
// certificate authority.
app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
});

module.exports = app;

