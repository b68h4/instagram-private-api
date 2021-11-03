[instagram-private-api](../../README.md) / [index](../../modules/index.md) / StoriesInsightsFeed

# Class: StoriesInsightsFeed

[index](../../modules/index.md).StoriesInsightsFeed

## Hierarchy

- [`Feed`](Feed.md)<[`StoriesInsightsFeedResponseRootObject`](../../interfaces/index/StoriesInsightsFeedResponseRootObject.md), [`StoriesInsightsFeedResponseEdgesItem`](../../interfaces/index/StoriesInsightsFeedResponseEdgesItem.md)\>

  ↳ **`StoriesInsightsFeed`**

## Table of contents

### Constructors

- [constructor](StoriesInsightsFeed.md#constructor)

### Properties

- [attemptOptions](StoriesInsightsFeed.md#attemptoptions)

### Accessors

- [items$](StoriesInsightsFeed.md#items$)

### Methods

- [deserialize](StoriesInsightsFeed.md#deserialize)
- [isMoreAvailable](StoriesInsightsFeed.md#ismoreavailable)
- [items](StoriesInsightsFeed.md#items)
- [observable](StoriesInsightsFeed.md#observable)
- [request](StoriesInsightsFeed.md#request)
- [serialize](StoriesInsightsFeed.md#serialize)
- [toPlain](StoriesInsightsFeed.md#toplain)

## Constructors

### constructor

• **new StoriesInsightsFeed**(`client`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `client` | [`IgApiClient`](IgApiClient.md) |

#### Inherited from

[Feed](Feed.md).[constructor](Feed.md#constructor)

#### Defined in

[src/core/repository.ts:7](https://github.com/Nerixyz/instagram-private-api/blob/0e0721c/src/core/repository.ts#L7)

## Properties

### attemptOptions

• **attemptOptions**: `Partial`<`AttemptOptions`<`any`\>\>

#### Inherited from

[Feed](Feed.md).[attemptOptions](Feed.md#attemptoptions)

#### Defined in

[src/core/feed.ts:10](https://github.com/Nerixyz/instagram-private-api/blob/0e0721c/src/core/feed.ts#L10)

## Accessors

### items$

• `get` **items$**(): `Observable`<`Item`[]\>

#### Returns

`Observable`<`Item`[]\>

#### Defined in

[src/core/feed.ts:18](https://github.com/Nerixyz/instagram-private-api/blob/0e0721c/src/core/feed.ts#L18)

## Methods

### deserialize

▸ **deserialize**(`data`): `void`

#### Parameters

| Name | Type |
| :------ | :------ |
| `data` | `string` |

#### Returns

`void`

#### Inherited from

[Feed](Feed.md).[deserialize](Feed.md#deserialize)

#### Defined in

[src/core/feed.ts:79](https://github.com/Nerixyz/instagram-private-api/blob/0e0721c/src/core/feed.ts#L79)

___

### isMoreAvailable

▸ **isMoreAvailable**(): `boolean`

#### Returns

`boolean`

#### Inherited from

[Feed](Feed.md).[isMoreAvailable](Feed.md#ismoreavailable)

#### Defined in

[src/core/feed.ts:87](https://github.com/Nerixyz/instagram-private-api/blob/0e0721c/src/core/feed.ts#L87)

___

### items

▸ **items**(): `Promise`<[`StoriesInsightsFeedResponseEdgesItem`](../../interfaces/index/StoriesInsightsFeedResponseEdgesItem.md)[]\>

#### Returns

`Promise`<[`StoriesInsightsFeedResponseEdgesItem`](../../interfaces/index/StoriesInsightsFeedResponseEdgesItem.md)[]\>

#### Overrides

[Feed](Feed.md).[items](Feed.md#items)

#### Defined in

[src/feeds/stories-insights.feed.ts:15](https://github.com/Nerixyz/instagram-private-api/blob/0e0721c/src/feeds/stories-insights.feed.ts#L15)

___

### observable

▸ **observable**(`semaphore?`, `attemptOptions?`): `Observable`<[`StoriesInsightsFeedResponseEdgesItem`](../../interfaces/index/StoriesInsightsFeedResponseEdgesItem.md)[]\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `semaphore?` | () => `Promise`<`any`\> |
| `attemptOptions?` | `Partial`<`AttemptOptions`<`any`\>\> |

#### Returns

`Observable`<[`StoriesInsightsFeedResponseEdgesItem`](../../interfaces/index/StoriesInsightsFeedResponseEdgesItem.md)[]\>

#### Inherited from

[Feed](Feed.md).[observable](Feed.md#observable)

#### Defined in

[src/core/feed.ts:21](https://github.com/Nerixyz/instagram-private-api/blob/0e0721c/src/core/feed.ts#L21)

___

### request

▸ **request**(): `Promise`<[`StoriesInsightsFeedResponseRootObject`](../../interfaces/index/StoriesInsightsFeedResponseRootObject.md)\>

#### Returns

`Promise`<[`StoriesInsightsFeedResponseRootObject`](../../interfaces/index/StoriesInsightsFeedResponseRootObject.md)\>

#### Overrides

[Feed](Feed.md).[request](Feed.md#request)

#### Defined in

[src/feeds/stories-insights.feed.ts:20](https://github.com/Nerixyz/instagram-private-api/blob/0e0721c/src/feeds/stories-insights.feed.ts#L20)

___

### serialize

▸ **serialize**(): `string`

#### Returns

`string`

#### Inherited from

[Feed](Feed.md).[serialize](Feed.md#serialize)

#### Defined in

[src/core/feed.ts:75](https://github.com/Nerixyz/instagram-private-api/blob/0e0721c/src/core/feed.ts#L75)

___

### toPlain

▸ **toPlain**(): `Record`<`string`, `any`\>

#### Returns

`Record`<`string`, `any`\>

#### Inherited from

[Feed](Feed.md).[toPlain](Feed.md#toplain)

#### Defined in

[src/core/feed.ts:83](https://github.com/Nerixyz/instagram-private-api/blob/0e0721c/src/core/feed.ts#L83)