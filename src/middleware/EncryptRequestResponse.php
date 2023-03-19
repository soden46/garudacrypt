<?php

namespace Soden46\GarudaCrypt\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Soden46\GarudaCrypt\GarudaCrypt;

class EncryptRequestResponse
{
    protected $garudacrypt;

    public function __construct()
    {
        $this->garudacrypt = GarudaCrypt::make();
    }

    public function handle(Request $request, Closure $next)
    {
        if ($request->header('X-REQUEST-ENCRYPTED')) {
            $this->modifyRequest($request);
        }

        $response = $next($request);
        if ($response instanceof JsonResponse) {
            $this->modifyResponse($request, $response);
        }

        return $response;
    }

    protected function modifyRequest(Request $request)
    {
        $decrypted = $request->payload ? $this->garudacrypt->decrypt($request->payload) : null;
        if ($decrypted) {
            $request->merge($decrypted);
            $request->replace($request->except('payload'));
        }
    }

    protected function modifyResponse(Request $request, JsonResponse $response)
    {
        if ($request->header('X-RESPONSE-ENCRYPTED')) {
            $payload = ['payload' => $this->garudacrypt->encrypt(json_decode($response->content(), true))];

            $response->setContent(json_encode($payload));
            $response->header('X-RESPONSE-ENCRYPTED', "1");
        }
    }
}
