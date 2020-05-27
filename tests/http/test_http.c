/*
 * Copyright 2017-2020 AVSystem <avsystem@avsystem.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <avs_commons_init.h>

#include <ctype.h>
#include <string.h>

#include <avsystem/commons/avs_errno.h>
#include <avsystem/commons/avs_list.h>
#include <avsystem/commons/avs_stream_netbuf.h>
#include <avsystem/commons/avs_unit_mocksock.h>
#include <avsystem/commons/avs_unit_test.h>

#include "test_http.h"

#include "src/http/avs_body_receivers.h"

#define MODULE_NAME http_test
#include <avs_x_log_config.h>

AVS_UNIT_GLOBAL_INIT(verbose) {
    if (!verbose) {
        avs_log_set_default_level(AVS_LOG_QUIET);
    }
}

expected_socket_t *avs_http_test_SOCKETS_TO_CREATE = NULL;

static avs_error_t test_socket_create(avs_net_socket_t **socket,
                                      avs_net_socket_type_t type) {
    expected_socket_t *removed_entry;
    removed_entry = AVS_LIST_DETACH(&avs_http_test_SOCKETS_TO_CREATE);
    AVS_UNIT_ASSERT_NOT_NULL(removed_entry);
    AVS_UNIT_ASSERT_EQUAL(type, removed_entry->type);
    *socket = removed_entry->socket;
    AVS_LIST_DELETE(&removed_entry);
    return (*socket) ? AVS_OK : avs_errno(AVS_ENOMEM);
}

avs_error_t avs_net_tcp_socket_create_TEST_WRAPPER(avs_net_socket_t **socket,
                                                   ...) {
    return test_socket_create(socket, AVS_NET_TCP_SOCKET);
}

avs_error_t avs_net_ssl_socket_create_TEST_WRAPPER(avs_net_socket_t **socket,
                                                   ...) {
    return test_socket_create(socket, AVS_NET_SSL_SOCKET);
}

void avs_http_test_expect_create_socket(avs_net_socket_t *socket,
                                        avs_net_socket_type_t type) {
    expected_socket_t *new_socket = AVS_LIST_NEW_ELEMENT(expected_socket_t);
    AVS_UNIT_ASSERT_NOT_NULL(new_socket);
    new_socket->socket = socket;
    new_socket->type = type;
    AVS_LIST_APPEND(&avs_http_test_SOCKETS_TO_CREATE, new_socket);
}

AVS_UNIT_TEST(http, full_request) {
    const char *tmp_data = NULL;
    char buffer[64];
    char *buffer_ptr = buffer;
    bool message_finished = false;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://www.zombo.com/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "www.zombo.com", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_POST,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 NULL, NULL));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_write_f(stream, "Welcome\n"));
    avs_unit_mocksock_assert_io_clean(socket);
    tmp_data = "POST / HTTP/1.1\r\n"
               "Host: www.zombo.com\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "Content-Length: 22\r\n"
               "\r\n"
               "Welcome\n"
               "to Zombo.com!\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 200 OK\r\n"
               "Transfer-Encoding: identity\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_write_f(stream, "to Zombo.com!\n"));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_finish_message(stream));
    avs_unit_mocksock_assert_io_clean(socket);
    tmp_data = "You can do anything\n"
               "at Zombo.com!\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    while (!message_finished) {
        size_t bytes_read;
        AVS_UNIT_ASSERT_SUCCESS(avs_stream_read(
                stream, &bytes_read, &message_finished, buffer_ptr,
                sizeof(buffer) - (buffer_ptr - buffer)));
        buffer_ptr += bytes_read;
    }
    AVS_UNIT_ASSERT_EQUAL(buffer_ptr - buffer, strlen(tmp_data));
    *buffer_ptr = '\0';
    AVS_UNIT_ASSERT_EQUAL_STRING(buffer, tmp_data);
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

AVS_UNIT_TEST(http, reconnect_fail) {
    const char *tmp_data = NULL;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://www.avsystem.com/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "www.avsystem.com", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_GET,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 NULL, NULL));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    tmp_data = "GET / HTTP/1.1\r\n"
               "Host: www.avsystem.com\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 200 OK\r\n"
               "Transfer-Encoding: identity\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_finish_message(stream));
    avs_unit_mocksock_assert_io_clean(socket);

    avs_unit_mocksock_expect_mid_close(socket);
    avs_unit_mocksock_expect_connect(socket, "www.avsystem.com", "80");
    avs_unit_mocksock_fail_command(socket, avs_errno(AVS_ECONNREFUSED));
    avs_error_t err = avs_stream_finish_message(stream);
    AVS_UNIT_ASSERT_EQUAL(err.category, AVS_ERRNO_CATEGORY);
    AVS_UNIT_ASSERT_EQUAL(err.code, AVS_ECONNREFUSED);
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

AVS_UNIT_TEST(http, advanced_request) {
    const char *tmp_data;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("HtTp://pentagon.osd.mil/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "pentagon.osd.mil", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_GET,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 "root", "12345"));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    AVS_UNIT_ASSERT_SUCCESS(avs_http_add_header(stream, "I-Am", "h4x0r"));
    tmp_data = "GET / HTTP/1.1\r\n" /* first request */
               "Host: pentagon.osd.mil\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "I-Am: h4x0r\r\n"
               "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 401 Unauthorized\r\n" /* first response */
               "WWW-Authenticate: Basic realm=\"JIGOKU DESU\"\r\n"
               "Set-Cookie: nyan=cat\r\n"
               "Set-Cookie2: nyan=azu\r\n"
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    tmp_data = "GET / HTTP/1.1\r\n" /* second request */
               "Host: pentagon.osd.mil\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "Authorization: Basic cm9vdDoxMjM0NQ==\r\n"
               "Cookie: $Version=\"1\"; nyan=azu\r\n"
               "I-Am: h4x0r\r\n"
               "\r\n"; /* no third request - fail after two 401's */
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 401 Unauthorized\r\n" /* second response */
               "WWW-Authenticate: Basic realm=\"JIGOKU DESU\"\r\n"
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    avs_error_t err = avs_stream_finish_message(stream);
    AVS_UNIT_ASSERT_EQUAL(err.category, AVS_HTTP_ERROR_CATEGORY);
    AVS_UNIT_ASSERT_EQUAL(err.code, 401);
    AVS_UNIT_ASSERT_EQUAL(avs_http_status_code(stream), 401);
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

AVS_UNIT_TEST(http, invalid_cookies) {
    const char *tmp_data;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://avsystem.com/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "avsystem.com", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_GET,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 "wacek", "ala123"));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    tmp_data = "GET / HTTP/1.1\r\n" /* first request */
               "Host: avsystem.com\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 200 OK\r\n" /* first response */
               "Set-Cookie: invalid\r\n"
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    avs_error_t err = avs_stream_finish_message(stream);
    AVS_UNIT_ASSERT_EQUAL(err.category, AVS_ERRNO_CATEGORY);
    AVS_UNIT_ASSERT_EQUAL(err.code, AVS_EPROTO);
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

AVS_UNIT_TEST(http, multiple_cookies) {
    const char *tmp_data;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://unicodesnowmanforyou.com/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "unicodesnowmanforyou.com", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_GET,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 "omae_wa", "mou_shindeiru"));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    tmp_data = "GET / HTTP/1.1\r\n" /* first request */
               "Host: unicodesnowmanforyou.com\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 401 Unauthorized\r\n" /* first response */
               "WWW-Authenticate: Basic realm=\"NANI?!\"\r\n"
               "Set-Cookie: sleeper=wake_up\r\n"
               "Set-Cookie: wake_up=sleeper\r\n"
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    tmp_data = "GET / HTTP/1.1\r\n" /* second request */
               "Host: unicodesnowmanforyou.com\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "Authorization: Basic b21hZV93YTptb3Vfc2hpbmRlaXJ1\r\n"
               "Cookie: sleeper=wake_up; wake_up=sleeper\r\n"
               "\r\n"; /* no third request - fail after two 401's */
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 401 Unauthorized\r\n" /* second response */
               "WWW-Authenticate: Basic realm=\"NANI?!\"\r\n"
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    avs_error_t err = avs_stream_finish_message(stream);
    AVS_UNIT_ASSERT_EQUAL(err.category, AVS_HTTP_ERROR_CATEGORY);
    AVS_UNIT_ASSERT_EQUAL(err.code, 401);
    AVS_UNIT_ASSERT_EQUAL(avs_http_status_code(stream), 401);
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

const char *const MONTY_PYTHON_RAW =
        "A customer enters a pet shop.\n"
        "Customer: 'Ello, I wish to register a complaint.\n"
        "(The owner does not respond.)\n"
        "C: 'Ello, Miss?\n"
        "Owner: What do you mean 'miss'?\n"
        "C: I'm sorry, I have a cold. I wish to make a complaint!\n"
        "O: We're closin' for lunch.\n"
        "C: Never mind that, my lad. I wish to complain about this parrot what "
        "I purchased not half an hour ago from this very boutique.\n"
        "O: Oh yes, the, uh, the Norwegian Blue...What's,uh...What's wrong "
        "with it?\n"
        "C: I'll tell you what's wrong with it, my lad. 'E's dead, that's "
        "what's wrong with it!\n"
        "O: No, no, 'e's uh,...he's resting.\n"
        "C: Look, matey, I know a dead parrot when I see one, and I'm looking "
        "at one right now.\n"
        "O: No no he's not dead, he's, he's restin'! Remarkable bird, the "
        "Norwegian Blue, idn'it, ay? Beautiful plumage!\n"
        "C: The plumage don't enter into it. It's stone dead.\n"
        "O: Nononono, no, no! 'E's resting!\n"
        "C: All right then, if he's restin', I'll wake him up!\n"
        "(shouting at the cage)\n"
        "'Ello, Mister Polly Parrot! I've got a lovely fresh cuttle fish for "
        "you if you show...(owner hits the cage)\n"
        "O: There, he moved!\n"
        "C: No, he didn't, that was you hitting the cage!\n"
        "O: I never!!\n"
        "C: Yes, you did!\n"
        "O: I never, never did anything...\n"
        "C: (yelling and hitting the cage repeatedly) 'ELLO POLLY!!!!!\n"
        "Testing! Testing! Testing! Testing! This is your nine o'clock alarm "
        "call!\n"
        "(Takes parrot out of the cage and thumps its head on the counter. "
        "Throws it up in the air and watches it plummet to the floor.)\n"
        "C: Now that's what I call a dead parrot.\n"
        "O: No, no.....No, 'e's stunned!\n"
        "C: STUNNED?!?\n"
        "O: Yeah! You stunned him, just as he was wakin' up! Norwegian Blues "
        "stun easily, major.\n"
        "C: Um...now look...now look, mate, I've definitely 'ad enough of "
        "this. That parrot is definitely deceased, and when I purchased it not "
        "'alf an hour ago, you assured me that its total lack of movement was "
        "due to it bein' tired and shagged out following a prolonged squawk.\n"
        "O: Well, he's...he's, ah...probably pining for the fjords.\n"
        "C: PININ' for the FJORDS?!?!?!? What kind of talk is that?, look, why "
        "did he fall flat on his back the moment I got 'im home?\n"
        "O: The Norwegian Blue prefers kippin' on it's back! Remarkable bird, "
        "id'nit, squire? Lovely plumage!\n"
        "C: Look, I took the liberty of examining that parrot when I got it "
        "home, and I discovered the only reason that it had been sitting on "
        "its perch in the first place was that it had been NAILED there.\n"
        "(pause)\n"
        "O: Well, o'course it was nailed there! If I hadn't nailed that bird "
        "down, it would have nuzzled up to those bars, bent 'em apart with its "
        "beak, and VOOM! Feeweeweewee!\n"
        "C: 'VOOM'?!? Mate, this bird wouldn't 'voom' if you put four million "
        "volts through it! 'E's bleedin' demised!\n"
        "O: No no! 'E's pining!\n"
        "C: 'E's not pinin'! 'E's passed on! This parrot is no more! He has "
        "ceased to be! 'E's expired and gone to meet 'is maker!\n"
        "'E's a stiff! Bereft of life, 'e rests in peace! If you hadn't nailed "
        "'im to the perch 'e'd be pushing up the daisies!\n"
        "\n"
        "'Is metabolic processes are now 'istory! 'E's off the twig!\n"
        "\n"
        "'E's kicked the bucket, 'e's shuffled off 'is mortal coil, run down "
        "the curtain and joined the bleedin' choir invisibile!!\n"
        "THIS IS AN EX-PARROT!!\n"
        "(pause)\n"
        "O: Well, I'd better replace it, then.\n"
        "(he takes a quick peek behind the counter)\n"
        "O: Sorry squire, I've had a look 'round the back of the shop, and uh, "
        "we're right out of parrots.\n"
        "C: I see. I see, I get the picture.\n"
        "O: I got a slug.\n"
        "(pause)\n"
        "C: (sweet as sugar) Pray, does it talk?\n"
        "O: Nnnnot really.\n"
        "C: WELL IT'S HARDLY A BLOODY REPLACEMENT, IS IT?!!?!!?\n"
        "O: Look, if you go to my brother's pet shop in Bolton, he'll replace "
        "the parrot for you.\n"
        "C: Bolton, eh? Very well.\n"
        "The customer leaves.\n"
        "The customer enters the same pet shop. The owner is putting on a "
        "false moustache.\n"
        "C: This is Bolton, is it?\n"
        "O: (with a fake mustache) No, it's Ipswitch.\n"
        "C: (looking at the camera) That's inter-city rail for you.\n"
        "The customer goes to the train station.\n"
        "He addresses a man standing behind a desk marked 'Complaints'.\n"
        "C: I wish to complain, British-Railways Person.\n"
        "Attendant: I DON'T HAVE TO DO THIS JOB, YOU KNOW!!!\n"
        "C: I beg your pardon...?\n"
        "A: I'm a qualified brain surgeon! I only do this job because I like "
        "being my own boss!\n"
        "C: Excuse me, this is irrelevant, isn't it?\n"
        "A: Yeah, well it's not easy to pad these python files out to 200 "
        "lines, you know.\n"
        "C: Well, I wish to complain. I got on the Bolton train and found "
        "myself deposited here in Ipswitch.\n"
        "A: No, this is Bolton.\n"
        "C: (to the camera) The pet shop man's brother was lying!!\n"
        "A: Can't blame British Rail for that.\n"
        "C: In that case, I shall return to the pet shop!\n"
        "He does.\n"
        "C: I understand this IS Bolton.\n"
        "O: (still with the fake mustache) Yes?\n"
        "C: You told me it was Ipswitch!\n"
        "O: ...It was a pun.\n"
        "C: (pause) A PUN?!?\n"
        "O: No, no...not a pun...What's that thing that spells the same "
        "backwards as forwards?\n"
        "C: (Long pause) A palindrome...?\n"
        "O: Yeah, that's it!\n"
        "C: It's not a palindrome! The palindrome of 'Bolton' would be "
        "'Notlob'!! It don't work!!\n"
        "O: Well, what do you want?\n"
        "C: I'm not prepared to pursue my line of inquiry any longer as I "
        "think this is getting too silly!\n"
        "Sergeant-Major: Quite agree, quite agree, too silly, far too "
        "silly...\n";

const char *const MONTY_PYTHON_PER_LINE_REQUEST =
        "FDF\r\n"
        "A customer enters a pet shop.\n"
        "Customer: 'Ello, I wish to register a complaint.\n"
        "(The owner does not respond.)\n"
        "C: 'Ello, Miss?\n"
        "Owner: What do you mean 'miss'?\n"
        "C: I'm sorry, I have a cold. I wish to make a complaint!\n"
        "O: We're closin' for lunch.\n"
        "C: Never mind that, my lad. I wish to complain about this parrot what "
        "I purchased not half an hour ago from this very boutique.\n"
        "O: Oh yes, the, uh, the Norwegian Blue...What's,uh...What's wrong "
        "with it?\n"
        "C: I'll tell you what's wrong with it, my lad. 'E's dead, that's "
        "what's wrong with it!\n"
        "O: No, no, 'e's uh,...he's resting.\n"
        "C: Look, matey, I know a dead parrot when I see one, and I'm looking "
        "at one right now.\n"
        "O: No no he's not dead, he's, he's restin'! Remarkable bird, the "
        "Norwegian Blue, idn'it, ay? Beautiful plumage!\n"
        "C: The plumage don't enter into it. It's stone dead.\n"
        "O: Nononono, no, no! 'E's resting!\n"
        "C: All right then, if he's restin', I'll wake him up!\n"
        "(shouting at the cage)\n"
        "'Ello, Mister Polly Parrot! I've got a lovely fresh cuttle fish for "
        "you if you show...(owner hits the cage)\n"
        "O: There, he moved!\n"
        "C: No, he didn't, that was you hitting the cage!\n"
        "O: I never!!\n"
        "C: Yes, you did!\n"
        "O: I never, never did anything...\n"
        "C: (yelling and hitting the cage repeatedly) 'ELLO POLLY!!!!!\n"
        "Testing! Testing! Testing! Testing! This is your nine o'clock alarm "
        "call!\n"
        "(Takes parrot out of the cage and thumps its head on the counter. "
        "Throws it up in the air and watches it plummet to the floor.)\n"
        "C: Now that's what I call a dead parrot.\n"
        "O: No, no.....No, 'e's stunned!\n"
        "C: STUNNED?!?\n"
        "O: Yeah! You stunned him, just as he was wakin' up! Norwegian Blues "
        "stun easily, major.\n"
        "C: Um...now look...now look, mate, I've definitely 'ad enough of "
        "this. That parrot is definitely deceased, and when I purchased it not "
        "'alf an hour ago, you assured me that its total lack of movement was "
        "due to it bein' tired and shagged out following a prolonged squawk.\n"
        "O: Well, he's...he's, ah...probably pining for the fjords.\n"
        "C: PININ' for the FJORDS?!?!?!? What kind of talk is that?, look, why "
        "did he fall flat on his back the moment I got 'im home?\n"
        "O: The Norwegian Blue prefers kippin' on it's back! Remarkable bird, "
        "id'nit, squire? Lovely plumage!\n"
        "C: Look, I took the liberty of examining that parrot when I got it "
        "home, and I discovered the only reason that it had been sitting on "
        "its perch in the first place was that it had been NAILED there.\n"
        "(pause)\n"
        "O: Well, o'course it was nailed there! If I hadn't nailed that bird "
        "down, it would have nuzzled up to those bars, bent 'em apart with its "
        "beak, and VOOM! Feeweeweewee!\n"
        "C: 'VOOM'?!? Mate, this bird wouldn't 'voom' if you put four million "
        "volts through it! 'E's bleedin' demised!\n"
        "O: No no! 'E's pining!\n"
        "C: 'E's not pinin'! 'E's passed on! This parrot is no more! He has "
        "ceased to be! 'E's expired and gone to meet 'is maker!\n"
        "'E's a stiff! Bereft of life, 'e rests in peace! If you hadn't nailed "
        "'im to the perch 'e'd be pushing up the daisies!\n"
        "\n"
        "'Is metabolic processes are now 'istory! 'E's off the twig!\n"
        "\n"
        "'E's kicked the bucket, 'e's shuffled off 'is mortal coil, run down "
        "the curtain and joined the bleedin' choir invisibile!!\n"
        "THIS IS AN EX-PARROT!!\n"
        "(pause)\n"
        "O: Well, I'd better replace it, then.\n"
        "(he takes a quick peek behind the counter)\n"
        "O: Sorry squire, I've had a look 'round the back of the shop, and uh, "
        "we're right out of parrots.\n"
        "C: I see. I see, I get the picture.\n"
        "O: I got a slug.\n"
        "(pause)\n"
        "C: (sweet as sugar) Pray, does it talk?\n"
        "O: Nnnnot really.\n"
        "C: WELL IT'S HARDLY A BLOODY REPLACEMENT, IS IT?!!?!!?\n"
        "O: Look, if you go to my brother's pet shop in Bolton, he'll replace "
        "the parrot for you.\n"
        "C: Bolton, eh? Very well.\n"
        "The customer leaves.\n"
        "The customer enters the same pet shop. The owner is putting on a "
        "false moustache.\n"
        "C: This is Bolton, is it?\n"
        "O: (with a fake mustache) No, it's Ipswitch.\n"
        "C: (looking at the camera) That's inter-city rail for you.\n"
        "The customer goes to the train station.\n"
        "He addresses a man standing behind a desk marked 'Complaints'.\n"
        "C: I wish to complain, British-Railways Person.\n"
        "Attendant: I DON'T HAVE TO DO THIS JOB, YOU KNOW!!!\n"
        "C: I beg your pardon...?\n"
        "\r\n"
        "420\r\n"
        "A: I'm a qualified brain surgeon! I only do this job because I like "
        "being my own boss!\n"
        "C: Excuse me, this is irrelevant, isn't it?\n"
        "A: Yeah, well it's not easy to pad these python files out to 200 "
        "lines, you know.\n"
        "C: Well, I wish to complain. I got on the Bolton train and found "
        "myself deposited here in Ipswitch.\n"
        "A: No, this is Bolton.\n"
        "C: (to the camera) The pet shop man's brother was lying!!\n"
        "A: Can't blame British Rail for that.\n"
        "C: In that case, I shall return to the pet shop!\n"
        "He does.\n"
        "C: I understand this IS Bolton.\n"
        "O: (still with the fake mustache) Yes?\n"
        "C: You told me it was Ipswitch!\n"
        "O: ...It was a pun.\n"
        "C: (pause) A PUN?!?\n"
        "O: No, no...not a pun...What's that thing that spells the same "
        "backwards as forwards?\n"
        "C: (Long pause) A palindrome...?\n"
        "O: Yeah, that's it!\n"
        "C: It's not a palindrome! The palindrome of 'Bolton' would be "
        "'Notlob'!! It don't work!!\n"
        "O: Well, what do you want?\n"
        "C: I'm not prepared to pursue my line of inquiry any longer as I "
        "think this is getting too silly!\n"
        "Sergeant-Major: Quite agree, quite agree, too silly, far too "
        "silly...\n\r\n"
        "0\r\n"
        "\r\n";

AVS_UNIT_TEST(http, chunked_request) {
    const char *tmp_data = NULL;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://monty.python/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "monty.python", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_POST,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 NULL, NULL));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    tmp_data = "POST / HTTP/1.1\r\n"
               "Host: monty.python\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "Expect: 100-continue\r\n"
               "Transfer-Encoding: chunked\r\n"
               "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 100 Continue\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    /* The text used in this test is 5119 bytes long.
     * This is to test writing more than buffer size, which is 4096. */
    tmp_data = MONTY_PYTHON_PER_LINE_REQUEST;
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 200 OK\r\n"
               "Transfer-Encoding: identity\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    tmp_data = MONTY_PYTHON_RAW;
    while (*tmp_data) {
        send_line(stream, &tmp_data);
    }
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_finish_message(stream));
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

AVS_UNIT_TEST(http, no_100_continue) {
    const char *tmp_data = NULL;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://monty.python/");
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "monty.python", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_POST,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 NULL, NULL));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    tmp_data = "POST / HTTP/1.1\r\n"
               "Host: monty.python\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "Expect: 100-continue\r\n"
               "Transfer-Encoding: chunked\r\n"
               "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    /* not sending 100 Continue here;
     * expecting it'll succeed anyway after timeout */
    tmp_data = MONTY_PYTHON_PER_LINE_REQUEST;
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = MONTY_PYTHON_RAW;
    while (*tmp_data) {
        send_line(stream, &tmp_data);
    }
    tmp_data = "HTTP/1.1 200 OK\r\n"
               "Transfer-Encoding: identity\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_finish_message(stream));
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

AVS_UNIT_TEST(http, error_417) {
    const char *tmp_data = NULL;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://monty.python/");
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "monty.python", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_POST,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 NULL, NULL));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    tmp_data = "POST / HTTP/1.1\r\n"
               "Host: monty.python\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "Expect: 100-continue\r\n"
               "Transfer-Encoding: chunked\r\n"
               "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 417 Expectation Failed\r\n"
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    tmp_data = "POST / HTTP/1.1\r\n"
               "Host: monty.python\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "Transfer-Encoding: chunked\r\n"
               "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = MONTY_PYTHON_PER_LINE_REQUEST;
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 200 OK\r\n"
               "Transfer-Encoding: identity\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    tmp_data = MONTY_PYTHON_RAW;
    while (*tmp_data) {
        send_line(stream, &tmp_data);
    }
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_finish_message(stream));
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

const char *const MONTY_PYTHON_BIG_REQUEST =
        "1E\r\n"
        "A customer enters a pet shop.\n"
        "\r\n"
        "13E1\r\n"
        "Customer: 'Ello, I wish to register a complaint.\n"
        "(The owner does not respond.)\n"
        "C: 'Ello, Miss?\n"
        "Owner: What do you mean 'miss'?\n"
        "C: I'm sorry, I have a cold. I wish to make a complaint!\n"
        "O: We're closin' for lunch.\n"
        "C: Never mind that, my lad. I wish to complain about this parrot what "
        "I purchased not half an hour ago from this very boutique.\n"
        "O: Oh yes, the, uh, the Norwegian Blue...What's,uh...What's wrong "
        "with it?\n"
        "C: I'll tell you what's wrong with it, my lad. 'E's dead, that's "
        "what's wrong with it!\n"
        "O: No, no, 'e's uh,...he's resting.\n"
        "C: Look, matey, I know a dead parrot when I see one, and I'm looking "
        "at one right now.\n"
        "O: No no he's not dead, he's, he's restin'! Remarkable bird, the "
        "Norwegian Blue, idn'it, ay? Beautiful plumage!\n"
        "C: The plumage don't enter into it. It's stone dead.\n"
        "O: Nononono, no, no! 'E's resting!\n"
        "C: All right then, if he's restin', I'll wake him up!\n"
        "(shouting at the cage)\n"
        "'Ello, Mister Polly Parrot! I've got a lovely fresh cuttle fish for "
        "you if you show...(owner hits the cage)\n"
        "O: There, he moved!\n"
        "C: No, he didn't, that was you hitting the cage!\n"
        "O: I never!!\n"
        "C: Yes, you did!\n"
        "O: I never, never did anything...\n"
        "C: (yelling and hitting the cage repeatedly) 'ELLO POLLY!!!!!\n"
        "Testing! Testing! Testing! Testing! This is your nine o'clock alarm "
        "call!\n"
        "(Takes parrot out of the cage and thumps its head on the counter. "
        "Throws it up in the air and watches it plummet to the floor.)\n"
        "C: Now that's what I call a dead parrot.\n"
        "O: No, no.....No, 'e's stunned!\n"
        "C: STUNNED?!?\n"
        "O: Yeah! You stunned him, just as he was wakin' up! Norwegian Blues "
        "stun easily, major.\n"
        "C: Um...now look...now look, mate, I've definitely 'ad enough of "
        "this. That parrot is definitely deceased, and when I purchased it not "
        "'alf an hour ago, you assured me that its total lack of movement was "
        "due to it bein' tired and shagged out following a prolonged squawk.\n"
        "O: Well, he's...he's, ah...probably pining for the fjords.\n"
        "C: PININ' for the FJORDS?!?!?!? What kind of talk is that?, look, why "
        "did he fall flat on his back the moment I got 'im home?\n"
        "O: The Norwegian Blue prefers kippin' on it's back! Remarkable bird, "
        "id'nit, squire? Lovely plumage!\n"
        "C: Look, I took the liberty of examining that parrot when I got it "
        "home, and I discovered the only reason that it had been sitting on "
        "its perch in the first place was that it had been NAILED there.\n"
        "(pause)\n"
        "O: Well, o'course it was nailed there! If I hadn't nailed that bird "
        "down, it would have nuzzled up to those bars, bent 'em apart with its "
        "beak, and VOOM! Feeweeweewee!\n"
        "C: 'VOOM'?!? Mate, this bird wouldn't 'voom' if you put four million "
        "volts through it! 'E's bleedin' demised!\n"
        "O: No no! 'E's pining!\n"
        "C: 'E's not pinin'! 'E's passed on! This parrot is no more! He has "
        "ceased to be! 'E's expired and gone to meet 'is maker!\n"
        "'E's a stiff! Bereft of life, 'e rests in peace! If you hadn't nailed "
        "'im to the perch 'e'd be pushing up the daisies!\n"
        "\n"
        "'Is metabolic processes are now 'istory! 'E's off the twig!\n"
        "\n"
        "'E's kicked the bucket, 'e's shuffled off 'is mortal coil, run down "
        "the curtain and joined the bleedin' choir invisibile!!\n"
        "THIS IS AN EX-PARROT!!\n"
        "(pause)\n"
        "O: Well, I'd better replace it, then.\n"
        "(he takes a quick peek behind the counter)\n"
        "O: Sorry squire, I've had a look 'round the back of the shop, and uh, "
        "we're right out of parrots.\n"
        "C: I see. I see, I get the picture.\n"
        "O: I got a slug.\n"
        "(pause)\n"
        "C: (sweet as sugar) Pray, does it talk?\n"
        "O: Nnnnot really.\n"
        "C: WELL IT'S HARDLY A BLOODY REPLACEMENT, IS IT?!!?!!?\n"
        "O: Look, if you go to my brother's pet shop in Bolton, he'll replace "
        "the parrot for you.\n"
        "C: Bolton, eh? Very well.\n"
        "The customer leaves.\n"
        "The customer enters the same pet shop. The owner is putting on a "
        "false moustache.\n"
        "C: This is Bolton, is it?\n"
        "O: (with a fake mustache) No, it's Ipswitch.\n"
        "C: (looking at the camera) That's inter-city rail for you.\n"
        "The customer goes to the train station.\n"
        "He addresses a man standing behind a desk marked 'Complaints'.\n"
        "C: I wish to complain, British-Railways Person.\n"
        "Attendant: I DON'T HAVE TO DO THIS JOB, YOU KNOW!!!\n"
        "C: I beg your pardon...?\n"
        "A: I'm a qualified brain surgeon! I only do this job because I like "
        "being my own boss!\n"
        "C: Excuse me, this is irrelevant, isn't it?\n"
        "A: Yeah, well it's not easy to pad these python files out to 200 "
        "lines, you know.\n"
        "C: Well, I wish to complain. I got on the Bolton train and found "
        "myself deposited here in Ipswitch.\n"
        "A: No, this is Bolton.\n"
        "C: (to the camera) The pet shop man's brother was lying!!\n"
        "A: Can't blame British Rail for that.\n"
        "C: In that case, I shall return to the pet shop!\n"
        "He does.\n"
        "C: I understand this IS Bolton.\n"
        "O: (still with the fake mustache) Yes?\n"
        "C: You told me it was Ipswitch!\n"
        "O: ...It was a pun.\n"
        "C: (pause) A PUN?!?\n"
        "O: No, no...not a pun...What's that thing that spells the same "
        "backwards as forwards?\n"
        "C: (Long pause) A palindrome...?\n"
        "O: Yeah, that's it!\n"
        "C: It's not a palindrome! The palindrome of 'Bolton' would be "
        "'Notlob'!! It don't work!!\n"
        "O: Well, what do you want?\n"
        "C: I'm not prepared to pursue my line of inquiry any longer as I "
        "think this is getting too silly!\n"
        "Sergeant-Major: Quite agree, quite agree, too silly, far too "
        "silly...\n\r\n"
        "0\r\n"
        "\r\n";

AVS_UNIT_TEST(http, big_chunked_request) {
    const char *tmp_data = NULL;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://python.monty/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "python.monty", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_POST,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 NULL, NULL));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    tmp_data = "POST / HTTP/1.1\r\n"
               "Host: python.monty\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "Expect: 100-continue\r\n"
               "Transfer-Encoding: chunked\r\n"
               "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 100 Continue\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    tmp_data = MONTY_PYTHON_BIG_REQUEST;
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 200 OK\r\n"
               "Transfer-Encoding: identity\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    tmp_data = MONTY_PYTHON_RAW;
    send_line(stream, &tmp_data);
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_write(stream, tmp_data, strlen(tmp_data)));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_finish_message(stream));
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

AVS_UNIT_TEST(http, redirect) {
    const char *tmp_data = NULL;
    size_t i;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *sockets[6];
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://www.nyan.cat/");
    memset(sockets, 0, sizeof(sockets));
    AVS_UNIT_ASSERT_NOT_NULL(client);
    for (i = 0; i < 6; ++i) {
        avs_unit_mocksock_create(&sockets[i]);
    }
    avs_http_test_expect_create_socket(sockets[0], AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(sockets[0], "www.nyan.cat", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_GET,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 NULL, NULL));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    tmp_data = "GET / HTTP/1.1\r\n"
               "Host: www.nyan.cat\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "\r\n";
    avs_unit_mocksock_expect_output(sockets[0], tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 302 Found\r\n"
               "Location: http://www.poteflon.pl/\r\n"
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_input(sockets[0], tmp_data, strlen(tmp_data));

    avs_http_test_expect_create_socket(sockets[1], AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(sockets[1], "www.poteflon.pl", "80");
    tmp_data = "GET / HTTP/1.1\r\n"
               "Host: www.poteflon.pl\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "\r\n";
    avs_unit_mocksock_expect_output(sockets[1], tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 307 Temporary Redirect\r\n"
               "Location: http://htf.atom.com/\r\n"
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_input(sockets[1], tmp_data, strlen(tmp_data));

    avs_http_test_expect_create_socket(sockets[2], AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(sockets[2], "htf.atom.com", "80");
    tmp_data = "GET / HTTP/1.1\r\n"
               "Host: htf.atom.com\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "\r\n";
    avs_unit_mocksock_expect_output(sockets[2], tmp_data, strlen(tmp_data));

    tmp_data = "HTTP/1.1 301 Moved Permanently\r\n"
               "Location: http://www.youtube.com/watch?v=dQw4w9WgXcQ\r\n"
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_input(sockets[2], tmp_data, strlen(tmp_data));

    avs_http_test_expect_create_socket(sockets[3], AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(sockets[3], "www.youtube.com", "80");
    tmp_data = "GET /watch?v=dQw4w9WgXcQ HTTP/1.1\r\n"
               "Host: www.youtube.com\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "\r\n";
    avs_unit_mocksock_expect_output(sockets[3], tmp_data, strlen(tmp_data));

    tmp_data = "HTTP/1.1 302 Found\r\n"
               "Location: http://isnickelbacktheworstbandever.tumblr.com/\r\n"
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_input(sockets[3], tmp_data, strlen(tmp_data));

    avs_http_test_expect_create_socket(sockets[4], AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(
            sockets[4], "isnickelbacktheworstbandever.tumblr.com", "80");
    tmp_data = "GET / HTTP/1.1\r\n"
               "Host: isnickelbacktheworstbandever.tumblr.com\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "\r\n";
    avs_unit_mocksock_expect_output(sockets[4], tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 307 Temporary Redirect\r\n"
               "Location: http://www.badumtss.net/\r\n"
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_input(sockets[4], tmp_data, strlen(tmp_data));

    avs_http_test_expect_create_socket(sockets[5], AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(sockets[5], "www.badumtss.net", "80");
    tmp_data = "GET / HTTP/1.1\r\n"
               "Host: www.badumtss.net\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "\r\n";
    avs_unit_mocksock_expect_output(sockets[5], tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 301 Moved Permanently\r\n"
               "Location: http://www.randomwebsite.com/\r\n"
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_input(sockets[5], tmp_data, strlen(tmp_data));

    avs_error_t err = avs_stream_finish_message(stream);
    AVS_UNIT_ASSERT_EQUAL(err.category, AVS_HTTP_ERROR_CATEGORY);
    AVS_UNIT_ASSERT_EQUAL(err.code, 301);
    AVS_UNIT_ASSERT_EQUAL(avs_http_status_code(stream), 301);
    avs_unit_mocksock_assert_io_clean(sockets[5]);
    avs_unit_mocksock_expect_shutdown(sockets[5]);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

AVS_UNIT_TEST(http, interleaving) {
    const char *tmp_data = NULL;
    char buffer[64];
    bool message_finished = false;
    size_t i;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://pudim.com.br/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "pudim.com.br", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_POST,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 NULL, NULL));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    tmp_data = "POST / HTTP/1.1\r\n"
               "Host: pudim.com.br\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 200 OK\r\n"
               "Transfer-Encoding: identity\r\n"
               "\r\n"
               "'Twas brillig, and the slithy toves\n"
               "Did gyre and gimble in the wabe;\n"
               "All mimsy were the borogoves,\n"
               "And the mome raths outgrabe.\n"
               "\n"
               "\"Beware the Jabberwock, my son!\n"
               "The jaws that bite, the claws that catch!\n"
               "Beware the Jubjub bird, and shun\n"
               "The frumious Bandersnatch!\"\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_finish_message(stream));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_getline(stream, NULL, &message_finished,
                                               buffer, sizeof(buffer)));
    for (i = 0; buffer[i]; ++i) {
        buffer[i] = (char) toupper(buffer[i]);
    }
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_write_f(stream, "%s\n", buffer));
    while (!message_finished) {
        avs_error_t err = avs_stream_getline(stream, NULL, &message_finished,
                                             buffer, sizeof(buffer));
        AVS_UNIT_ASSERT_TRUE(avs_is_ok(err) || message_finished);
        if (message_finished) {
            break;
        }
        for (i = 0; buffer[i]; ++i) {
            buffer[i] = (char) toupper(buffer[i]);
        }
        AVS_UNIT_ASSERT_SUCCESS(avs_stream_write_f(stream, "%s\n", buffer));
    }
    avs_unit_mocksock_assert_io_clean(socket);
    tmp_data = "POST / HTTP/1.1\r\n"
               "Host: pudim.com.br\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "Content-Length: 264\r\n"
               "\r\n"
               "'TWAS BRILLIG, AND THE SLITHY TOVES\n"
               "DID GYRE AND GIMBLE IN THE WABE;\n"
               "ALL MIMSY WERE THE BOROGOVES,\n"
               "AND THE MOME RATHS OUTGRABE.\n"
               "\n"
               "\"BEWARE THE JABBERWOCK, MY SON!\n"
               "THE JAWS THAT BITE, THE CLAWS THAT CATCH!\n"
               "BEWARE THE JUBJUB BIRD, AND SHUN\n"
               "THE FRUMIOUS BANDERSNATCH!\"\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 200 OK\r\n"
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    avs_unit_mocksock_expect_mid_close(socket);
    avs_unit_mocksock_expect_connect(socket, "pudim.com.br", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_finish_message(stream));
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

AVS_UNIT_TEST(http, interleaving_error) {
    const char *tmp_data = NULL;
    char buffer[64];
    bool message_finished = false;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://www.omfgdogs.com/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "www.omfgdogs.com", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_POST,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 NULL, NULL));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    tmp_data = "POST / HTTP/1.1\r\n"
               "Host: www.omfgdogs.com\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    // Note that Content-Length is larger than the data provided
    tmp_data =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 4981\r\n"
            "\r\n"
            "Far far away, behind the word mountains, far from the countries\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_finish_message(stream));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_getline(stream, NULL, &message_finished,
                                               buffer, sizeof(buffer)));
    AVS_UNIT_ASSERT_FAILED(avs_stream_finish_message(stream));
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

AVS_UNIT_TEST(http, send_headers_fail) {
    const char *tmp_data = NULL;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://www.avsystem.com/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "www.avsystem.com", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_GET,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 NULL, NULL));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    tmp_data = "GET / HTTP/1.1\r\n"
               "Host: www.avsystem.com\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    avs_unit_mocksock_output_fail(socket, avs_errno(AVS_EIO));
    AVS_UNIT_ASSERT_FAILED(avs_stream_finish_message(stream));
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

#ifdef AVS_COMMONS_NET_WITH_IPV6
AVS_UNIT_TEST(http, ipv6_host_header_has_square_brackets) {
    const char *tmp_data = NULL;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://[::1:2:3:4]:1234/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "::1:2:3:4", "1234");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_GET,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 NULL, NULL));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    tmp_data = "GET / HTTP/1.1\r\n"
               "Host: [::1:2:3:4]:1234\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    avs_unit_mocksock_output_fail(socket, avs_errno(AVS_EIO));
    AVS_UNIT_ASSERT_FAILED(avs_stream_finish_message(stream));
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}
#endif // AVS_COMMONS_NET_WITH_IPV6

AVS_UNIT_TEST(http, invalid_uri_protocol) {
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_url_t *url = avs_url_parse("coap://127.0.0.1");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    avs_error_t err =
            avs_http_open_stream(&(avs_stream_t *) { NULL }, client,
                                 AVS_HTTP_GET, AVS_HTTP_CONTENT_IDENTITY, url,
                                 NULL, NULL);
    AVS_UNIT_ASSERT_FAILED(err);
    AVS_UNIT_ASSERT_EQUAL(err.category, AVS_ERRNO_CATEGORY);
    AVS_UNIT_ASSERT_EQUAL(err.code, AVS_EINVAL);
    avs_url_free(url);
    avs_http_free(client);
}
