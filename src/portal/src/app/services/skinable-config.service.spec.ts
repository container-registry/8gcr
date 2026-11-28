// Copyright Project Harbor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
import { TestBed, inject, getTestBed } from '@angular/core/testing';
import {
    HttpClientTestingModule,
    HttpTestingController,
} from '@angular/common/http/testing';
import { SkinableConfig } from './skinable-config.service';

describe('SkinableConfig', () => {
    let injector: TestBed;
    let service: SkinableConfig;
    let httpMock: HttpTestingController;
    let product = {
        name: '',
        logo: '',
        introduction: '',
    };
    let mockCustomSkinData = {
        headerBgColor: {
            darkMode: '',
            lightMode: '',
        },
        loginBgImg: '',
        loginTitle: '',
        product: product,
    };

    beforeEach(() => {
        TestBed.configureTestingModule({
            imports: [HttpClientTestingModule],
            providers: [SkinableConfig],
        });
        injector = getTestBed();
        service = injector.get(SkinableConfig);
        httpMock = injector.get(HttpTestingController);
    });

    it('should be created', inject(
        [SkinableConfig],
        (service1: SkinableConfig) => {
            expect(service1).toBeTruthy();
        }
    ));
    it('getCustomFile() should return data', () => {
        service.getCustomFile().subscribe(res => {
            expect(res).toEqual(mockCustomSkinData);
        });

        const req = httpMock.expectOne('setting.json?buildTimeStamp=0');
        expect(req.request.method).toBe('GET');
        req.flush(mockCustomSkinData);
        expect(service.getSkinConfig()).toEqual(mockCustomSkinData);
        expect(service.getSkinConfig().product).toEqual(product);
    });
    it('setTitleIcon() should replace every tab icon with the custom logo', () => {
        const added: HTMLLinkElement[] = [];
        ['icon', 'icon', 'apple-touch-icon'].forEach(rel => {
            const link = document.createElement('link');
            link.rel = rel;
            link.href = 'favicon.ico';
            document.head.appendChild(link);
            added.push(link);
        });
        service.getCustomFile().subscribe();
        httpMock
            .expectOne('setting.json?buildTimeStamp=0')
            .flush({ product: { ...product, logo: 'custom.png' } });

        service.setTitleIcon();

        const icons = Array.from(
            document.querySelectorAll<HTMLLinkElement>('link[rel~="icon"]')
        );
        expect(icons.length).toBe(1);
        expect(icons[0].getAttribute('href')).toBe('images/custom.png');
        expect(document.querySelector('link[rel="apple-touch-icon"]')).toBe(
            added[2]
        );
        icons.forEach(link => link.remove());
        added[2].remove();
    });
});
