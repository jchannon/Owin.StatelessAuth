(function () {
    'use strict';

    var app = angular.module('owinstatelessauthexample', ['LocalForageModule'])
        .controller('appCtrl', [
            '$scope', '$localForage', function ($scope, $localForage) {
                // Start fresh
                $localForage.clearAll();

                $scope.user = 'fred';
                $scope.password = 'securepwd';
                $scope.secureresponse = '';

                $scope.getToken = function () {
                    $http({
                        method: 'POST',
                        url: '/login',
                        data: {
                            "user": $scope.user,
                            "password": $scope.password,
                        }
                    })
                        .success(function (data, status) {
                            console.log('All ok : ' + data);
                            $localForage.setItem('mysecuretoken', data);
                        })
                        .error(function (data, status) {
                            console.log('Oops : ' + data);
                        });

                };

                $scope.getsecureresponse = function () {
                    $localForage.get('mysecuretoken').then(function (data) {
                        $http({
                            method: 'GET',
                            url: '/',
                            headers: { 'Authorization': data }

                        })
                       .success(function (data, status) {
                           console.log('All secure : ' + data);
                           $scope.secureresponse = data;
                       })
                       .error(function (data, status) {
                           console.log('Oops : ' + data);
                       });
                    });

                };
            }]);

})();
